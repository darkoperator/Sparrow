//! Per-finding facts (agent accuracy T1): the enrichment step that runs after detection and stores
//! `finding_facts` for the persistence / consent / MFA families. Every case is built in the
//! STORED shape of its tables (lower-case UPNs, normalized IPs, cmdlet parameters as a map).

#[path = "common/detect.rs"]
mod detect;

use chrono::{DateTime, TimeZone, Utc};
use detect::{insert_row, insert_ual};
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::enrich::facts::{FindingFacts, Target};
use sparrow_core::detect::enrich::{EnrichState, FACTS_VERSION, enrichment_state, rebuild};
use sparrow_core::detect::load::{LoadedRule, RuleSet, load_rules, rule_sha256};
use sparrow_core::detect::rule::Rule;
use sparrow_core::detect::run::{DetectOptions, run};
use sparrow_core::profile::tenant::{DomainAction, set_domain};
use std::collections::BTreeMap;

const T: &str = "t1";
const ALICE: &str = "alice@contoso.example";
const IP: &str = "198.51.100.7";

fn at(day: u32, h: u32, m: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, day, h, m, 0).unwrap()
}

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

fn opts() -> DetectOptions {
    DetectOptions {
        now: Some(at(20, 12, 0)),
        ..DetectOptions::default()
    }
}

fn new_case() -> Case {
    let case = Case::in_memory().unwrap();
    insert_row(&case, "tenant", T, json!({"tenant_key": T}));
    detect::collection_of(&case, T);
    case
}

fn domain(case: &Case, d: &str) {
    insert_row(
        case,
        "tenant_domains",
        T,
        json!({"tenant_key": T, "domain": d, "source": "derived_upn", "rows_seen": 1}),
    );
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

/// A UAL New-InboxRule as the normalizer stores it: cmdlet parameters in `parameters`.
fn new_inbox_rule(case: &Case, upn: &str, ip: &str, t: DateTime<Utc>, params: serde_json::Value) {
    insert_ual(
        case,
        T,
        json!({"operation": "New-InboxRule", "workload": "Exchange", "record_type": 1,
               "record_type_name": "ExchangeAdmin", "result_status": "True",
               "user_upn": upn, "client_ip": ip, "event_time": iso(t), "parameters": params,
               "data_completeness": "full"}),
    );
}

fn trace(case: &Case, sender: &str, recipient: &str, t: DateTime<Utc>) {
    insert_row(
        case,
        "message_trace",
        T,
        json!({"sender": sender, "recipient": recipient, "received": iso(t), "status": "Delivered"}),
    );
}

/// The stored facts of the finding `rule_id` raised for `actor`.
fn facts_of(case: &Case, rule_id: &str, actor: &str) -> FindingFacts {
    let text: String = case
        .conn()
        .query_row(
            "SELECT CAST(ff.facts AS VARCHAR) FROM finding_facts ff JOIN findings f USING (finding_id) \
             WHERE f.rule_id = ? AND lower(f.actor_upn) = ?",
            [rule_id, actor],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("no facts for {rule_id} {actor}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn dump(case: &Case, sql: &str) -> Vec<String> {
    let mut st = case.conn().prepare(sql).unwrap();
    st.query_map([], |r| {
        let mut cols = Vec::new();
        for i in 0..r.as_ref().column_count() {
            cols.push(format!("{:?}", r.get::<_, duckdb::types::Value>(i)?));
        }
        Ok(cols.join("|"))
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

fn builtin() -> RuleSet {
    load_rules(&DataDirs::default()).unwrap()
}

#[test]
fn a_forward_set_from_a_familiar_ip_reports_the_earlier_days() {
    let mut case = new_case();
    domain(&case, "contoso.example");
    // The tenant's capture starts with another user's sign-in on 28 Feb.
    signin(
        &case,
        "carol@contoso.example",
        "203.0.113.9",
        Utc.with_ymd_and_hms(2026, 2, 28, 8, 0, 0).unwrap(),
        0,
    );
    // Alice signs in from the address on three earlier days (twice on the 2nd) ...
    signin(&case, ALICE, IP, at(1, 9, 0), 0);
    signin(&case, ALICE, IP, at(2, 9, 0), 0);
    signin(&case, ALICE, IP, at(2, 15, 0), 0);
    signin(&case, ALICE, IP, at(3, 9, 0), 0);
    // ... a failure, another user's sign-in from the same address, and a later sign-in do not count.
    signin(
        &case,
        ALICE,
        IP,
        Utc.with_ymd_and_hms(2026, 2, 28, 9, 0, 0).unwrap(),
        50126,
    );
    signin(
        &case,
        "carol@contoso.example",
        IP,
        Utc.with_ymd_and_hms(2026, 2, 27, 9, 0, 0).unwrap(),
        0,
    );
    signin(&case, ALICE, IP, at(5, 9, 0), 0);
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE, "ForwardTo": "SMTP:Bob@Partner.Example."}),
    );
    // Two earlier messages between Alice and Bob (one each way), one after the rule, one with someone else.
    trace(&case, ALICE, "bob@partner.example", at(1, 11, 0));
    trace(&case, "bob@partner.example", ALICE, at(2, 11, 0));
    trace(&case, ALICE, "bob@partner.example", at(6, 11, 0));
    trace(
        &case,
        "carol@contoso.example",
        "bob@partner.example",
        at(1, 12, 0),
    );

    let report = run(&mut case, &builtin(), &opts()).unwrap();
    assert_eq!(report.enrich.error, None);
    assert!(report.enrich.facts_rows >= 1, "{:?}", report.enrich);
    assert!(report.phases.iter().any(|p| p.name == "enrich"));

    let f = facts_of(&case, "SPW-HAWK-010", ALICE);
    assert_eq!(f.facts_version, FACTS_VERSION);
    assert_eq!(
        f.window_start,
        Some(Utc.with_ymd_and_hms(2026, 2, 27, 9, 0, 0).unwrap())
    );
    assert_eq!(f.actor_ips.len(), 1, "{f:?}");
    let ip = &f.actor_ips[0];
    assert_eq!(ip.ip, IP);
    assert_eq!(ip.user_signin_days_before, Some(3));
    assert_eq!(ip.user_first_signin, Some(at(1, 9, 0)));
    assert!(!ip.spray_source);
    assert_eq!(
        f.targets,
        Some(vec![Target {
            address: "bob@partner.example".into(),
            domain: "partner.example".into(),
            scope: "external".into(),
            prior_messages: Some(2),
        }])
    );
    // SPW-MAIL-004 (external forwarding) is in the same family and gets the same target.
    let m = facts_of(&case, "SPW-MAIL-004", ALICE);
    assert_eq!(m.targets, f.targets);
    // Every stored row is of the current version and run.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM finding_facts WHERE facts_version = 1 AND computed_run_id = 1"
        ),
        count(&case, "SELECT count(*) FROM finding_facts")
    );
}

#[test]
fn prior_messages_is_null_without_any_message_trace() {
    let mut case = new_case();
    domain(&case, "contoso.example");
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE, "ForwardTo": "bob@partner.example"}),
    );
    run(&mut case, &builtin(), &opts()).unwrap();
    let f = facts_of(&case, "SPW-HAWK-010", ALICE);
    let targets = f.targets.expect("a forwarding finding has targets");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].prior_messages, None);
    // No sign-ins at all: the window is unknown and no earlier day exists.
    assert_eq!(f.window_start, None);
    assert_eq!(f.actor_ips[0].user_signin_days_before, Some(0));
    assert_eq!(f.actor_ips[0].user_first_signin, None);
}

#[test]
fn an_internal_and_self_target_are_internal() {
    let mut case = new_case();
    // contoso.example is derived from the users table; fabrikam.example is an analyst override.
    insert_row(&case, "users", T, json!({"upn": ALICE}));
    set_domain(
        &mut case,
        Some(T),
        "fabrikam.example",
        DomainAction::Add,
        "analyst:test",
    )
    .unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM tenant_domains"), 2);
    trace(
        &case,
        "zed@elsewhere.example",
        "nobody@elsewhere.example",
        at(1, 1, 0),
    );
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE,
               "ForwardTo": "carol@fabrikam.example;Alice@Contoso.example",
               "RedirectTo": "dave@eu.contoso.example",
               "ForwardAsAttachmentTo": "eve@evil.example"}),
    );
    // The collected rule state carries Exchange's display spelling.
    insert_row(
        &case,
        "inbox_rules",
        T,
        json!({"mailbox_upn": ALICE, "name": "fw", "enabled": true,
               "forward_to": ["\"Carol\" [SMTP:carol@fabrikam.example]", "\"Mallory\" [SMTP:mallory@evil.example]"],
               "collected_at": iso(at(10, 0, 0))}),
    );
    run(&mut case, &builtin(), &opts()).unwrap();
    let f = facts_of(&case, "SPW-HAWK-010", ALICE);
    let got: Vec<(String, String, String)> = f
        .targets
        .expect("targets")
        .into_iter()
        .map(|t| (t.address, t.domain, t.scope))
        .collect();
    let want: Vec<(String, String, String)> = [
        ("alice@contoso.example", "contoso.example", "internal"),
        ("carol@fabrikam.example", "fabrikam.example", "internal"),
        ("dave@eu.contoso.example", "eu.contoso.example", "internal"),
        ("eve@evil.example", "evil.example", "external"),
        ("mallory@evil.example", "evil.example", "external"),
    ]
    .iter()
    .map(|(a, d, s)| (a.to_string(), d.to_string(), s.to_string()))
    .collect();
    assert_eq!(got, want);
}

#[test]
fn a_self_forward_is_internal_even_without_tenant_domains() {
    let mut case = new_case();
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE, "ForwardTo": "alice@contoso.example;x@contoso.example"}),
    );
    run(&mut case, &builtin(), &opts()).unwrap();
    let f = facts_of(&case, "SPW-HAWK-010", ALICE);
    let scopes: Vec<(String, String)> = f
        .targets
        .unwrap()
        .into_iter()
        .map(|t| (t.address, t.scope))
        .collect();
    assert_eq!(
        scopes,
        vec![
            ("alice@contoso.example".to_string(), "internal".to_string()),
            ("x@contoso.example".to_string(), "external".to_string()),
        ]
    );
}

fn rule_from(id: &str, severity: &str, stage: &str) -> LoadedRule {
    let text = format!(
        "id: {id}\ntitle: title of {id}\nversion: 1\nstatus: experimental\nseverity: {severity}\n{stage}analyst_guidance: g\nsource: mailboxes\nmatch:\n  forwarding_smtp_address: {{exists: true}}\ngroup_by: [actor_upn]\ntests:\n  - name: p\n    records: []\n    expect_hits: 1\n  - name: n\n    records: []\n    expect_hits: 0\n"
    );
    let rule: Rule = serde_norway::from_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    let sha256 = rule_sha256(&rule, &BTreeMap::new(), &BTreeMap::new());
    LoadedRule {
        path: format!("test:{id}"),
        sha256,
        rule,
    }
}

fn set_of(rules: Vec<LoadedRule>) -> RuleSet {
    RuleSet {
        rules,
        lists: BTreeMap::new(),
        list_meta: BTreeMap::new(),
        warnings: vec![],
    }
}

#[test]
fn other_signals_exclude_the_finding_itself_and_cap_at_five() {
    let mut case = new_case();
    for upn in [ALICE, "bob@contoso.example"] {
        insert_row(
            &case,
            "mailboxes",
            T,
            json!({"upn": upn, "forwarding_smtp_address": "x@evil.example", "collected_at": iso(at(10, 0, 0))}),
        );
    }
    let sev = [
        ("SPW-T-001", "low"),
        ("SPW-T-002", "critical"),
        ("SPW-T-003", "info"),
        ("SPW-T-004", "high"),
        ("SPW-T-005", "medium"),
        ("SPW-T-006", "high"),
        ("SPW-T-007", "low"),
    ];
    let mut rules: Vec<LoadedRule> = sev
        .iter()
        .map(|(id, s)| rule_from(id, s, "stage: persistence\n"))
        .collect();
    // A rule without a stage still counts as another signal, but gets no facts of its own.
    rules.push(rule_from("SPW-T-008", "medium", ""));
    let report = run(&mut case, &set_of(rules), &opts()).unwrap();
    assert_eq!(report.findings_new, 16);
    assert_eq!(report.enrich.facts_rows, 14, "7 staged rules x 2 actors");
    assert_eq!(count(&case, "SELECT count(*) FROM finding_facts"), 14);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM finding_facts JOIN findings USING (finding_id) WHERE rule_id = 'SPW-T-008'"
        ),
        0
    );

    let rank = |s: &str| {
        ["critical", "high", "medium", "low", "info"]
            .iter()
            .position(|x| *x == s)
            .unwrap()
    };
    let mut all: Vec<(usize, String, String)> = dump(
        &case,
        "SELECT finding_id || ' ' || rule_id || ' ' || severity FROM findings WHERE actor_upn = 'alice@contoso.example'",
    )
    .into_iter()
    .map(|l| {
        let l = l.trim_start_matches("Text(\"").trim_end_matches("\")").to_string();
        let p: Vec<&str> = l.split(' ').collect();
        (rank(p[2]), p[0].to_string(), p[1].to_string())
    })
    .collect();
    // Finding-list order: severity, then last_seen (equal here), then finding_id.
    all.sort();
    assert_eq!(all.len(), 8);
    for (id, _) in &sev {
        let f = facts_of(&case, id, ALICE);
        assert_eq!(f.other_signals.total, 7, "{id}: 8 findings minus itself");
        let got: Vec<&str> = f
            .other_signals
            .items
            .iter()
            .map(|s| s.rule_id.as_str())
            .collect();
        let want: Vec<&str> = all
            .iter()
            .filter(|(_, _, r)| r != id)
            .take(5)
            .map(|(_, _, r)| r.as_str())
            .collect();
        assert_eq!(got, want, "{id}");
        assert!(!got.contains(id));
        assert!(
            f.other_signals
                .items
                .iter()
                .all(|s| s.first_seen == Some(at(10, 0, 0)))
        );
        assert_eq!(f.targets.as_ref().map(|t| t.len()), Some(1));
    }
}

#[test]
fn the_window_edge_is_reported() {
    let mut case = new_case();
    domain(&case, "contoso.example");
    // The tenant's first sign-in is the rule's own moment (not strictly before it), then one later.
    signin(&case, ALICE, IP, at(4, 10, 0), 0);
    signin(&case, ALICE, IP, at(4, 10, 30), 0);
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE, "ForwardTo": "bob@partner.example"}),
    );
    run(&mut case, &builtin(), &opts()).unwrap();
    let f = facts_of(&case, "SPW-HAWK-010", ALICE);
    assert_eq!(f.window_start, Some(at(4, 10, 0)));
    assert_eq!(f.actor_ips[0].user_signin_days_before, Some(0));
    assert_eq!(f.actor_ips[0].user_first_signin, None);
}

#[test]
fn a_failing_rebuild_keeps_detection_successful_and_records_the_error() {
    let mut case = new_case();
    domain(&case, "contoso.example");
    signin(&case, ALICE, IP, at(1, 9, 0), 0);
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE, "ForwardTo": "bob@partner.example"}),
    );
    let set = builtin();
    let first = run(&mut case, &set, &opts()).unwrap();
    assert_eq!(first.enrich.error, None);
    let before = dump(&case, "SELECT * FROM finding_facts ORDER BY finding_id");
    assert!(!before.is_empty());
    let meta = |case: &Case| {
        dump(
            case,
            "SELECT key || '=' || value FROM case_meta WHERE key LIKE 'enrichment%' ORDER BY key",
        )
    };
    assert_eq!(
        meta(&case),
        vec!["Text(\"enrichment_run_id=1\")".to_string()]
    );

    // The rebuild needs tenant_domains; without it the rebuild fails after it emptied the table.
    case.conn()
        .execute_batch("ALTER TABLE tenant_domains RENAME TO tenant_domains_away")
        .unwrap();
    let r = rebuild(case.conn_mut(), &set, 99).unwrap();
    let err = r.error.expect("the rebuild failed");
    assert!(err.contains("tenant_domains"), "{err}");
    assert_eq!(
        dump(&case, "SELECT * FROM finding_facts ORDER BY finding_id"),
        before
    );
    let m = meta(&case);
    assert_eq!(m.len(), 2, "{m:?}");
    assert!(
        m[0].contains("enrichment_error=") && m[0].contains("tenant_domains"),
        "{m:?}"
    );
    assert_eq!(m[1], "Text(\"enrichment_run_id=1\")");

    // Detection itself still succeeds (a rule needing tenant_domains errors on its own).
    let second = run(&mut case, &set, &opts()).unwrap();
    assert!(second.enrich.error.is_some());
    assert!(
        second.warnings.iter().any(|w| w.contains("enrichment")),
        "{:?}",
        second.warnings
    );
    assert_eq!(
        dump(&case, "SELECT * FROM finding_facts ORDER BY finding_id"),
        before
    );

    // A later successful rebuild clears the error and restamps the rows.
    case.conn()
        .execute_batch("ALTER TABLE tenant_domains_away RENAME TO tenant_domains")
        .unwrap();
    let ok = rebuild(case.conn_mut(), &set, 7).unwrap();
    assert_eq!(ok.error, None);
    assert_eq!(ok.facts_rows as usize, before.len());
    assert_eq!(
        meta(&case),
        vec!["Text(\"enrichment_run_id=7\")".to_string()]
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM finding_facts WHERE computed_run_id = 7"
        ),
        before.len() as i64
    );
}

#[test]
fn prior_messages_is_null_for_a_tenant_without_message_trace() {
    // Two tenants: only t2 has message trace. A t1 target must read "unknown", not "0 messages".
    let mut case = new_case();
    domain(&case, "contoso.example");
    const T2: &str = "t2";
    insert_row(&case, "tenant", T2, json!({"tenant_key": T2}));
    detect::collection_of(&case, T2);
    insert_row(
        &case,
        "tenant_domains",
        T2,
        json!({"tenant_key": T2, "domain": "fabrikam.example", "source": "derived_upn", "rows_seen": 1}),
    );
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE, "ForwardTo": "bob@partner.example"}),
    );
    let carol = "carol@fabrikam.example";
    insert_ual(
        &case,
        T2,
        json!({"operation": "New-InboxRule", "workload": "Exchange", "record_type": 1,
               "record_type_name": "ExchangeAdmin", "result_status": "True",
               "user_upn": carol, "client_ip": IP, "event_time": iso(at(4, 10, 0)),
               "parameters": {"Name": "fw", "Mailbox": carol, "ForwardTo": "bob@partner.example"},
               "data_completeness": "full"}),
    );
    insert_row(
        &case,
        "message_trace",
        T2,
        json!({"sender": carol, "recipient": "bob@partner.example", "received": iso(at(1, 11, 0)), "status": "Delivered"}),
    );
    // Alice's own mail to Bob was traced in t2's collection: still not t1 evidence.
    insert_row(
        &case,
        "message_trace",
        T2,
        json!({"sender": ALICE, "recipient": "bob@partner.example", "received": iso(at(1, 12, 0)), "status": "Delivered"}),
    );
    run(&mut case, &builtin(), &opts()).unwrap();
    let a = facts_of(&case, "SPW-HAWK-010", ALICE).targets.unwrap();
    assert_eq!(a[0].prior_messages, None, "t1 has no message trace");
    let c = facts_of(&case, "SPW-HAWK-010", carol).targets.unwrap();
    assert_eq!(c[0].prior_messages, Some(1));
}

#[test]
fn a_missing_evidence_time_gives_no_earlier_day_count() {
    let mut case = new_case();
    domain(&case, "contoso.example");
    signin(&case, ALICE, IP, at(1, 9, 0), 0);
    signin(&case, ALICE, IP, at(2, 9, 0), 0);
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE, "ForwardTo": "bob@partner.example"}),
    );
    trace(&case, ALICE, "bob@partner.example", at(1, 11, 0));
    let set = builtin();
    run(&mut case, &set, &opts()).unwrap();
    assert_eq!(
        facts_of(&case, "SPW-HAWK-010", ALICE).actor_ips[0].user_signin_days_before,
        Some(2)
    );
    // The same evidence without a time cannot be compared with the sign-ins.
    case.conn()
        .execute_batch("UPDATE finding_evidence SET event_time = NULL")
        .unwrap();
    let r = rebuild(case.conn_mut(), &set, 1).unwrap();
    assert_eq!(r.error, None);
    let f = facts_of(&case, "SPW-HAWK-010", ALICE);
    assert_eq!(f.actor_ips.len(), 1);
    assert_eq!(f.actor_ips[0].user_signin_days_before, None);
    assert_eq!(f.actor_ips[0].user_first_signin, None);
    assert_eq!(f.targets.unwrap()[0].prior_messages, None);
    // The JSON says null, not 0.
    let text: String = case
        .conn()
        .query_row(
            "SELECT CAST(facts->'$.actor_ips[0].user_signin_days_before' AS VARCHAR) FROM finding_facts \
             JOIN findings USING (finding_id) WHERE rule_id = 'SPW-HAWK-010'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(text, "null");
}

#[test]
fn enrichment_state_is_the_reader_check() {
    let mut case = new_case();
    domain(&case, "contoso.example");
    new_inbox_rule(
        &case,
        ALICE,
        IP,
        at(4, 10, 0),
        json!({"Name": "fw", "Mailbox": ALICE, "ForwardTo": "bob@partner.example"}),
    );
    let set = builtin();
    assert_eq!(enrichment_state(case.conn()).unwrap(), EnrichState::Never);
    run(&mut case, &set, &opts()).unwrap();
    assert_eq!(
        enrichment_state(case.conn()).unwrap(),
        EnrichState::Ok { run_id: 1 }
    );

    // A failed rebuild with its marker written: Failed.
    case.conn()
        .execute_batch("ALTER TABLE tenant_domains RENAME TO tenant_domains_away")
        .unwrap();
    run(&mut case, &set, &opts()).unwrap();
    match enrichment_state(case.conn()).unwrap() {
        EnrichState::Failed { reason } => assert!(reason.contains("tenant_domains"), "{reason}"),
        s => panic!("{s:?}"),
    }
    case.conn()
        .execute_batch("ALTER TABLE tenant_domains_away RENAME TO tenant_domains")
        .unwrap();
    run(&mut case, &set, &opts()).unwrap();
    assert_eq!(
        enrichment_state(case.conn()).unwrap(),
        EnrichState::Ok { run_id: 3 }
    );

    // Run 4's rebuild fails AND so does writing its failure marker (case_meta unwritable): the
    // rows and marker of run 3 remain, so the state must be Stale, never Ok.
    case.conn()
        .execute_batch(
            "INSERT INTO detection_runs SELECT 4, tenant_key, rule_id, rule_version, rule_sha256, status, \
             reason, hits, duration_ms, started_at FROM detection_runs WHERE run_id = 3 LIMIT 1; \
             ALTER TABLE tenant_domains RENAME TO tenant_domains_away; \
             ALTER TABLE case_meta RENAME TO case_meta_away;",
        )
        .unwrap();
    assert!(
        rebuild(case.conn_mut(), &set, 4).is_err(),
        "the marker write failed"
    );
    case.conn()
        .execute_batch(
            "ALTER TABLE case_meta_away RENAME TO case_meta; \
             ALTER TABLE tenant_domains_away RENAME TO tenant_domains;",
        )
        .unwrap();
    assert_eq!(
        enrichment_state(case.conn()).unwrap(),
        EnrichState::Stale {
            enriched_run: 3,
            latest_run: 4
        }
    );
}
