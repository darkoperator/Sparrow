//! The readers of the enrichment tables (agent accuracy T4): `read::accounts`, the `facts` of `finding_show`, the
//! `context` of its evidence rows, and the `addresses` section of `pivot_user`. Every case is built in the stored
//! shape of its tables and detected with test rules.

#[path = "common/detect.rs"]
mod detect;

use chrono::{DateTime, TimeZone, Utc};
use detect::{insert_row, insert_ual};
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::case::read::{self, FactsField};
use sparrow_core::detect::load::{LoadedRule, RuleSet, rule_sha256};
use sparrow_core::detect::rule::Rule;
use sparrow_core::detect::run::{DetectOptions, run};
use std::collections::BTreeMap;

const T1: &str = "t1";
const T2: &str = "t2";
const ALICE: &str = "alice@contoso.example";
const BOB: &str = "bob@contoso.example";
const CAROL: &str = "carol@contoso.example";
const DAVE: &str = "dave@other.example";

fn at(day: u32, h: u32, m: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, day, h, m, 0).unwrap()
}

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
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

/// A forwarding mailbox: persistence stage, so its finding gets facts. High severity.
fn forwarding_rule() -> LoadedRule {
    rule_from(
        "SPW-T-001",
        "high",
        "stage: persistence\nsource: mailboxes\nmatch:\n  forwarding_smtp_address: {exists: true}\ngroup_by: [actor_upn]",
    )
}

/// A failed sign-in (50126): medium, one stage, no facts; its evidence carries a context.
fn failure_rule() -> LoadedRule {
    rule_from(
        "SPW-T-002",
        "medium",
        "stage: suspicious_sign_in\nsql: |\n  SELECT s.record_key, 'signins' AS source_table, s.event_time, s.user_upn AS actor_upn, s.ip AS ip,\n         json_object('why', 'wrong password') AS context\n  FROM signins s WHERE s.error_code = 50126\ngroup_by: [actor_upn]",
    )
}

/// The same failure with two stages (so the account outranks a one-stage account of the same severity).
fn two_stage_rule() -> LoadedRule {
    rule_from(
        "SPW-T-003",
        "medium",
        "stage: [suspicious_sign_in, mail_access]\nsql: |\n  SELECT s.record_key, 'signins' AS source_table, s.event_time, s.user_upn AS actor_upn, s.ip AS ip,\n         CAST(NULL AS JSON) AS context\n  FROM signins s WHERE s.error_code = 50053\ngroup_by: [actor_upn]",
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

fn tenant(case: &Case, key: &str, domain: &str) {
    insert_row(case, "tenant", key, json!({"tenant_key": key}));
    detect::collection_of(case, key);
    insert_row(
        case,
        "tenant_domains",
        key,
        json!({"tenant_key": key, "domain": domain, "source": "derived_upn", "rows_seen": 1}),
    );
}

fn signin(case: &Case, t: &str, upn: &str, ip: &str, when: DateTime<Utc>, code: i64) {
    insert_row(
        case,
        "signins",
        t,
        json!({"user_upn": upn, "ip": ip, "event_time": iso(when), "error_code": code,
               "event_type": "interactive", "is_interactive": true, "app_name": "Office 365"}),
    );
}

/// Alice: a forwarding mailbox (high, facts). Bob: one wrong password (medium, one stage). Carol: a locked
/// account (medium, two stages). Dave, in a second tenant: a wrong password later than Bob's.
fn detected() -> Case {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    tenant(&case, T2, "other.example");
    insert_row(
        &case,
        "mailboxes",
        T1,
        json!({"upn": ALICE, "forwarding_smtp_address": "x@evil.example", "collected_at": iso(at(10, 0, 0))}),
    );
    signin(&case, T1, ALICE, "203.0.113.10", at(1, 8, 0), 0);
    // Alice's mail is read from an address she never signed in from.
    insert_row(
        &case,
        "mail_items_accessed",
        T1,
        json!({"item_key": "mia-1", "event_time": iso(at(3, 9, 0)), "user_upn": ALICE, "client_ip": "198.51.100.20",
               "access_type": "bind", "folder_path": "\\Inbox", "time_tz_assumed": false}),
    );
    signin(&case, T1, BOB, "192.0.2.5", at(2, 9, 0), 50126);
    signin(&case, T1, CAROL, "192.0.2.6", at(4, 9, 0), 50053);
    signin(&case, T2, DAVE, "192.0.2.7", at(3, 9, 0), 50126);
    let opts = DetectOptions {
        now: Some(at(20, 12, 0)),
        ..DetectOptions::default()
    };
    let report = run(
        &mut case,
        &set_of(vec![forwarding_rule(), failure_rule(), two_stage_rule()]),
        &opts,
    )
    .unwrap();
    assert_eq!(report.enrich.error, None, "{report:?}");
    assert_eq!(report.enrich.accounts, 4);
    case
}

fn set() -> RuleSet {
    set_of(vec![forwarding_rule(), failure_rule(), two_stage_rule()])
}

fn finding_of(case: &Case, rule: &str, actor: &str) -> String {
    case.conn()
        .query_row(
            "SELECT finding_id FROM findings WHERE rule_id = ? AND lower(actor_upn) = ?",
            [rule, actor],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("no finding {rule} for {actor}: {e}"))
}

/// What a case detected before the feature looks like: migrated, the two tables empty and no enrichment key.
fn pre_feature(case: &Case) {
    case.conn()
        .execute_batch(
            "DELETE FROM finding_facts; DELETE FROM account_rollup; \
             DELETE FROM case_meta WHERE key IN ('enrichment_run_id', 'enrichment_error');",
        )
        .unwrap();
}

/// Enrichment ran for an older detection run than the latest one.
fn stale(case: &Case) {
    case.conn()
        .execute(
            "INSERT OR REPLACE INTO case_meta (key, value) VALUES ('enrichment_run_id', '0')",
            [],
        )
        .unwrap();
}

fn enrichment_failed(case: &Case, msg: &str) {
    case.conn()
        .execute(
            "INSERT OR REPLACE INTO case_meta (key, value) VALUES ('enrichment_error', ?)",
            [msg],
        )
        .unwrap();
}

#[test]
fn accounts_come_in_reader_order_and_can_be_filtered_and_limited() {
    let case = detected();
    let all = read::accounts(case.conn(), None, None).unwrap();
    let order: Vec<&str> = all.accounts.iter().map(|a| a.upn.as_str()).collect();
    // high first; then two stages beats one stage; then the earlier first_suspicious (Bob day 2, Dave day 3).
    assert_eq!(order, [ALICE, CAROL, BOB, DAVE]);
    assert_eq!((all.total, all.truncated), (4, false));
    assert!(all.warnings.is_empty(), "{:?}", all.warnings);
    // A limit keeps the head of that order and says so.
    let two = read::accounts(case.conn(), None, Some(2)).unwrap();
    let got: Vec<&str> = two.accounts.iter().map(|a| a.upn.as_str()).collect();
    assert_eq!(got, [ALICE, CAROL]);
    assert_eq!((two.total, two.truncated), (4, true));
    // A limit at or over the total is not truncated; a tenant filter counts only its own accounts.
    assert!(
        !read::accounts(case.conn(), None, Some(4))
            .unwrap()
            .truncated
    );
    let t2 = read::accounts(case.conn(), Some(T2), None).unwrap();
    assert_eq!(
        t2.accounts
            .iter()
            .map(|a| a.upn.as_str())
            .collect::<Vec<_>>(),
        [DAVE]
    );
    assert_eq!((t2.total, t2.truncated), (1, false));
    let t1 = read::accounts(case.conn(), Some(T1), Some(1)).unwrap();
    assert_eq!((t1.accounts.len(), t1.total, t1.truncated), (1, 3, true));
    // Alice's roll-up is the stored one: persistence stage, the MIA-only address listed.
    let alice = &all.accounts[0];
    assert_eq!(alice.worst_severity, "high");
    assert!(
        alice.addresses.iter().any(|a| a.ip == "198.51.100.20"),
        "{alice:#?}"
    );
}

#[test]
fn facts_are_present_for_a_persistence_finding_and_absent_for_the_others() {
    let case = detected();
    let alice =
        read::finding_show(case.conn(), &finding_of(&case, "SPW-T-001", ALICE), &set()).unwrap();
    let Some(FactsField::Present { facts }) = alice.facts.clone() else {
        panic!("facts expected: {:?}", alice.facts);
    };
    assert_eq!(facts.facts_version, 1);
    assert!(
        facts
            .targets
            .as_ref()
            .is_some_and(|t| t[0].address == "x@evil.example")
    );
    // A finding of a rule outside the facts families has neither key.
    let bob =
        read::finding_show(case.conn(), &finding_of(&case, "SPW-T-002", BOB), &set()).unwrap();
    assert!(bob.facts.is_none());
    let json = serde_json::to_value(&bob).unwrap();
    assert!(json.get("facts").is_none() && json.get("facts_unavailable").is_none());
    let json = serde_json::to_value(&alice).unwrap();
    assert!(json["facts"]["actor_ips"].is_array(), "{json}");
    assert!(json.get("facts_unavailable").is_none());
}

#[test]
fn facts_are_unavailable_for_a_case_detected_before_the_feature() {
    let case = detected();
    let id = finding_of(&case, "SPW-T-001", ALICE);
    pre_feature(&case);
    let d = read::finding_show(case.conn(), &id, &set()).unwrap();
    let Some(FactsField::Unavailable { facts_unavailable }) = &d.facts else {
        panic!("facts_unavailable expected: {:?}", d.facts);
    };
    assert!(
        facts_unavailable.contains("detection has not run since this version")
            && facts_unavailable.contains("`sparrow detect`"),
        "{facts_unavailable}"
    );
    let json = serde_json::to_value(&d).unwrap();
    assert_eq!(json["facts_unavailable"], *facts_unavailable);
    assert!(json.get("facts").is_none());
    // A finding outside the families still has neither key.
    let bob =
        read::finding_show(case.conn(), &finding_of(&case, "SPW-T-002", BOB), &set()).unwrap();
    assert!(bob.facts.is_none());
}

#[test]
fn a_recorded_enrichment_error_makes_the_facts_unavailable_with_its_message() {
    let case = detected();
    let id = finding_of(&case, "SPW-T-001", ALICE);
    enrichment_failed(&case, "Binder Error: no such column");
    let d = read::finding_show(case.conn(), &id, &set()).unwrap();
    let Some(FactsField::Unavailable { facts_unavailable }) = d.facts else {
        panic!("facts_unavailable expected");
    };
    assert!(
        facts_unavailable.contains("Binder Error: no such column"),
        "{facts_unavailable}"
    );
    // The roll-up rows of the earlier run are not offered either: fail closed.
    let page = read::accounts(case.conn(), None, None).unwrap();
    assert!(page.accounts.is_empty());
    assert!(
        page.warnings
            .iter()
            .any(|w| w.contains("Binder Error: no such column")),
        "{:?}",
        page.warnings
    );
}

#[test]
fn a_finding_in_the_families_with_no_facts_row_is_unavailable_not_silent() {
    let case = detected();
    let id = finding_of(&case, "SPW-T-001", ALICE);
    case.conn()
        .execute("DELETE FROM finding_facts WHERE finding_id = ?", [&id])
        .unwrap();
    let d = read::finding_show(case.conn(), &id, &set()).unwrap();
    let Some(FactsField::Unavailable { facts_unavailable }) = d.facts else {
        panic!("facts_unavailable expected");
    };
    assert!(
        facts_unavailable.contains("`sparrow detect`"),
        "{facts_unavailable}"
    );
}

#[test]
fn accounts_of_a_pre_feature_case_are_an_empty_list_with_a_warning_naming_the_fix() {
    let case = detected();
    pre_feature(&case);
    let page = read::accounts(case.conn(), None, None).unwrap();
    assert!(page.accounts.is_empty());
    assert_eq!((page.total, page.truncated), (0, false));
    assert_eq!(page.warnings.len(), 1, "{:?}", page.warnings);
    assert!(
        page.warnings[0].contains("detection has not run since this version")
            && page.warnings[0].contains("`sparrow detect`"),
        "{:?}",
        page.warnings
    );
    // The same case once detection has run has no warning (and a case with no findings is not "unavailable").
    let mut empty = Case::in_memory().unwrap();
    tenant(&empty, T1, "contoso.example");
    let opts = DetectOptions {
        now: Some(at(20, 12, 0)),
        ..DetectOptions::default()
    };
    run(&mut empty, &set(), &opts).unwrap();
    let page = read::accounts(empty.conn(), None, None).unwrap();
    assert!(
        page.accounts.is_empty() && page.warnings.is_empty(),
        "{page:?}"
    );
}

#[test]
fn every_evidence_row_has_its_stored_context_or_null() {
    let case = detected();
    let bob =
        read::finding_show(case.conn(), &finding_of(&case, "SPW-T-002", BOB), &set()).unwrap();
    assert!(!bob.evidence.is_empty());
    assert_eq!(
        bob.evidence[0].context,
        Some(json!({"why": "wrong password"}))
    );
    let alice =
        read::finding_show(case.conn(), &finding_of(&case, "SPW-T-001", ALICE), &set()).unwrap();
    assert!(!alice.evidence.is_empty());
    assert!(alice.evidence.iter().all(|e| e.context.is_none()));
    // Serialised, the key is always there.
    let v = serde_json::to_value(&alice).unwrap();
    assert!(
        v["evidence"][0]
            .as_object()
            .unwrap()
            .contains_key("context"),
        "{v}"
    );
    assert!(v["evidence"][0]["context"].is_null());
    let v = serde_json::to_value(&bob).unwrap();
    assert_eq!(
        v["evidence"][0]["context"],
        json!({"why": "wrong password"})
    );
}

#[test]
fn pivot_user_lists_the_accounts_roll_up_addresses() {
    let case = detected();
    let p = read::pivot_user(case.conn(), "ALICE@contoso.example", 50).unwrap();
    let s = p
        .sections
        .iter()
        .find(|s| s.name == "addresses")
        .expect("an addresses section");
    let ips: Vec<&str> = s.rows.iter().map(|r| r["ip"].as_str().unwrap()).collect();
    assert!(ips.contains(&"198.51.100.20"), "{ips:?}");
    assert_eq!((s.total, s.truncated), (s.rows.len() as i64, false));
    assert!(s.rows[0]["reasons"].is_array() && s.rows[0].get("in_user_signins").is_some());
    // The cap applies and is reported.
    let capped = read::pivot_user(case.conn(), ALICE, 1).unwrap();
    let c = capped
        .sections
        .iter()
        .find(|s| s.name == "addresses")
        .unwrap();
    assert_eq!(c.rows.len(), 1);
    assert_eq!(c.total, s.total);
    assert_eq!(c.truncated, s.total > 1);
    // A user with no roll-up row: the section is there and empty.
    let none = read::pivot_user(case.conn(), "nobody@contoso.example", 50).unwrap();
    let n = none
        .sections
        .iter()
        .find(|s| s.name == "addresses")
        .unwrap();
    assert_eq!((n.rows.len(), n.total, n.truncated), (0, 0, false));
    // And in a case detected before the feature.
    pre_feature(&case);
    let p = read::pivot_user(case.conn(), ALICE, 50).unwrap();
    assert!(
        p.sections
            .iter()
            .any(|s| s.name == "addresses" && s.rows.is_empty())
    );
}

/// Keeps `insert_ual` used for a UAL-only address, like the roll-up tests do.
#[test]
fn an_address_seen_only_in_the_ual_is_listed_too() {
    let mut case = Case::in_memory().unwrap();
    tenant(&case, T1, "contoso.example");
    insert_row(
        &case,
        "mailboxes",
        T1,
        json!({"upn": ALICE, "forwarding_smtp_address": "x@evil.example", "collected_at": iso(at(10, 0, 0))}),
    );
    insert_ual(
        &case,
        T1,
        json!({"operation": "MailItemsAccessed", "workload": "Exchange", "record_type": 50,
               "record_type_name": "ExchangeItemAggregated", "result_status": "Succeeded",
               "user_upn": ALICE, "client_ip": "198.51.100.30", "event_time": iso(at(4, 10, 0)),
               "data_completeness": "full"}),
    );
    let opts = DetectOptions {
        now: Some(at(20, 12, 0)),
        ..DetectOptions::default()
    };
    run(&mut case, &set_of(vec![forwarding_rule()]), &opts).unwrap();
    let p = read::pivot_user(case.conn(), ALICE, 50).unwrap();
    let s = p.sections.iter().find(|s| s.name == "addresses").unwrap();
    assert!(
        s.rows.iter().any(|r| r["ip"] == "198.51.100.30"),
        "{:?}",
        s.rows
    );
}

/// The four states of the enrichment decide every reader the same way: only a current enrichment shows facts,
/// accounts and addresses; the others say why, naming the fix.
#[test]
fn all_four_enrichment_states_decide_facts_accounts_and_addresses() {
    // (setup, a text the reason must contain, whether readers show anything)
    type Setup = fn(&Case);
    let states: [(&str, Setup, &str); 4] = [
        ("ok", |_| {}, ""),
        (
            "never",
            pre_feature,
            "detection has not run since this version",
        ),
        (
            "failed",
            |c| enrichment_failed(c, "Binder Error: boom"),
            "Binder Error: boom",
        ),
        ("stale", stale, "but the latest run is"),
    ];
    for (name, setup, reason) in states {
        let case = detected();
        let id = finding_of(&case, "SPW-T-001", ALICE);
        setup(&case);
        let d = read::finding_show(case.conn(), &id, &set()).unwrap();
        let page = read::accounts(case.conn(), None, None).unwrap();
        let p = read::pivot_user(case.conn(), ALICE, 50).unwrap();
        let addr = p.sections.iter().find(|s| s.name == "addresses").unwrap();
        if name == "ok" {
            assert!(
                matches!(d.facts, Some(FactsField::Present { .. })),
                "{name}"
            );
            assert_eq!(page.accounts.len(), 4, "{name}");
            assert!(page.warnings.is_empty() && !addr.rows.is_empty(), "{name}");
        } else {
            let Some(FactsField::Unavailable { facts_unavailable }) = &d.facts else {
                panic!("{name}: facts_unavailable expected, got {:?}", d.facts);
            };
            assert!(
                facts_unavailable.contains(reason),
                "{name}: {facts_unavailable}"
            );
            assert!(
                facts_unavailable.contains("`sparrow detect`"),
                "{name}: {facts_unavailable}"
            );
            assert!(
                page.accounts.is_empty(),
                "{name}: stale or failed rows must not be offered"
            );
            assert!(
                page.warnings.len() == 1 && page.warnings[0].contains(reason),
                "{name}: {:?}",
                page.warnings
            );
            assert!(addr.rows.is_empty() && addr.total == 0, "{name}");
        }
    }
}

/// The real state check is "enriched run EQUALS the latest run": a recorded run id that is not the latest is stale
/// whichever side it is on (a case whose detection history was replaced), and readers fail closed on it too.
#[test]
fn an_enrichment_run_id_that_is_not_the_latest_is_stale_either_way() {
    let case = detected();
    let id = finding_of(&case, "SPW-T-001", ALICE);
    case.conn()
        .execute(
            "INSERT OR REPLACE INTO case_meta (key, value) VALUES ('enrichment_run_id', '99')",
            [],
        )
        .unwrap();
    let d = read::finding_show(case.conn(), &id, &set()).unwrap();
    let Some(FactsField::Unavailable { facts_unavailable }) = d.facts else {
        panic!("facts_unavailable expected");
    };
    assert!(
        facts_unavailable.contains("run 99") && facts_unavailable.contains("`sparrow detect`"),
        "{facts_unavailable}"
    );
    assert!(
        read::accounts(case.conn(), None, None)
            .unwrap()
            .accounts
            .is_empty()
    );
}
