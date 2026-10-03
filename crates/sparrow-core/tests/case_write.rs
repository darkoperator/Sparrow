#[path = "common/detect.rs"]
mod detect;
#[path = "common/synth.rs"]
mod synth;

use chrono::{TimeZone, Utc};
use serde_json::json;
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::indicators::{
    IndicatorType, Verdict, add_indicator, list_indicators, remove_indicator, set_verdict,
};
use sparrow_core::case::write::FindingStatus as S;
use sparrow_core::case::{audit, review, write};
use sparrow_core::detect::load::{LoadedRule, RuleSet, rule_sha256};
use sparrow_core::detect::rule::Rule;
use sparrow_core::detect::run::{DetectOptions, run};
use sparrow_core::{Case, Error};
use std::collections::BTreeMap;

fn case_with_finding() -> Case {
    let c = Case::in_memory().unwrap();
    c.conn()
        .execute_batch(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, created_by, created_at, updated_at)
             VALUES ('f1', 'fp1', 't1', 'SPW-ID-004', 1, 'x', 'high', 'AiTM', 'rule', now(), now());",
        )
        .unwrap();
    c
}

fn agent() -> Actor {
    Actor::agent("claude", Some("carlos")).unwrap()
}

fn carlos() -> Reviewer {
    Reviewer::analyst("carlos").unwrap()
}

fn col(c: &Case, sql: &str) -> Option<String> {
    c.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn micros(c: &Case, sql: &str) -> i64 {
    c.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn status(c: &Case) -> Option<String> {
    col(c, "SELECT CAST(status AS VARCHAR) FROM findings")
}

fn review_state(c: &Case) -> Option<String> {
    col(c, "SELECT CAST(review_state AS VARCHAR) FROM findings")
}

fn is_decision_error(e: &Error) -> bool {
    matches!(e, Error::Decision(_))
}

// ---------------------------------------------------------------- finding decisions

#[test]
fn agent_can_confirm_and_it_is_tagged_pending() {
    let c = case_with_finding();
    let e = write::set_finding_status(
        c.conn(),
        &agent(),
        "f1",
        S::Confirmed,
        Some("session replay from VPS"),
    )
    .unwrap();
    assert_eq!(e.action, "set_status");
    assert_eq!(
        (e.object_type.as_str(), e.object_id.as_str()),
        ("finding", "f1")
    );
    assert_eq!(e.actor, "agent:claude");
    assert_eq!(e.on_behalf_of.as_deref(), Some("analyst:carlos"));
    assert_eq!(e.reason.as_deref(), Some("session replay from VPS"));
    assert_eq!(status(&c), Some("confirmed".into()));
    assert_eq!(
        col(&c, "SELECT decided_by FROM findings"),
        Some("agent:claude".into())
    );
    assert_eq!(
        col(&c, "SELECT on_behalf_of FROM findings"),
        Some("analyst:carlos".into())
    );
    assert_eq!(review_state(&c), Some("pending_review".into()));
    assert_eq!(
        col(&c, "SELECT disposition_reason FROM findings"),
        Some("session replay from VPS".into())
    );
    let before = e.before.unwrap();
    assert_eq!(before["status"], "new");
    assert_eq!(before["review_state"], serde_json::Value::Null);
    assert_eq!(e.after.unwrap()["status"], "confirmed");
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 1);
}

#[test]
fn decided_at_is_the_audit_timestamp() {
    let c = case_with_finding();
    let e = write::set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).unwrap();
    assert_eq!(
        micros(&c, "SELECT epoch_us(decided_at) FROM findings"),
        e.ts.timestamp_micros()
    );
    let r = review::review_accept(c.conn(), &carlos(), "finding", "f1", e.seq, None).unwrap();
    assert_eq!(
        micros(&c, "SELECT epoch_us(reviewed_at) FROM findings"),
        r.ts.timestamp_micros()
    );
}

#[test]
fn closing_requires_a_reason() {
    let c = case_with_finding();
    for s in [S::Confirmed, S::FalsePositive, S::Benign] {
        let err = write::set_finding_status(c.conn(), &agent(), "f1", s, None).unwrap_err();
        assert!(is_decision_error(&err), "{err:?}");
        assert!(write::set_finding_status(c.conn(), &agent(), "f1", s, Some("  ")).is_err());
    }
    assert!(
        audit::log(c.conn(), None).unwrap().is_empty(),
        "a refused write is not audited"
    );
    assert_eq!(status(&c), Some("new".into()));
    assert_eq!(review_state(&c), None);
    write::set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).unwrap();
    assert_eq!(status(&c), Some("in_review".into()));
}

#[test]
fn status_strings_parse() {
    for s in S::ALL {
        assert_eq!(S::parse(s.as_str()).unwrap(), s);
    }
    assert!(is_decision_error(&S::parse("closed").unwrap_err()));
}

#[test]
fn unknown_finding_writes_nothing() {
    let c = case_with_finding();
    let err = write::set_finding_status(c.conn(), &agent(), "nope", S::InReview, None).unwrap_err();
    assert!(is_decision_error(&err), "{err:?}");
    assert!(write::assign_finding(c.conn(), &agent(), "nope", "dana").is_err());
    assert!(write::ack_rule_update(c.conn(), &agent(), "nope").is_err());
    assert!(audit::log(c.conn(), None).unwrap().is_empty());
}

#[test]
fn assign_and_ack_rule_update_are_decisions() {
    let c = case_with_finding();
    let e = write::assign_finding(c.conn(), &agent(), "f1", "dana").unwrap();
    assert_eq!(e.action, "assign");
    assert_eq!(
        col(&c, "SELECT assigned_to FROM findings"),
        Some("dana".into())
    );
    assert!(write::assign_finding(c.conn(), &agent(), "f1", "  ").is_err());
    // Nothing to acknowledge yet.
    assert!(is_decision_error(
        &write::ack_rule_update(c.conn(), &agent(), "f1").unwrap_err()
    ));
    c.conn()
        .execute_batch("UPDATE findings SET rule_updated = true")
        .unwrap();
    let e = write::ack_rule_update(c.conn(), &agent(), "f1").unwrap();
    assert_eq!(e.action, "ack_rule_update");
    assert_eq!(e.before.unwrap()["rule_updated"], true);
    assert_eq!(
        col(&c, "SELECT CAST(rule_updated AS VARCHAR) FROM findings"),
        Some("false".into())
    );
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 2);
}

#[test]
fn audit_failure_rolls_back_the_change() {
    let c = case_with_finding();
    // Break the chain so append refuses: the status change must not persist.
    write::set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).unwrap();
    c.conn()
        .execute("UPDATE audit_trail SET actor = 'x'", [])
        .unwrap();
    let err =
        write::set_finding_status(c.conn(), &agent(), "f1", S::NeedsMoreData, None).unwrap_err();
    assert!(matches!(err, Error::ChainBroken(_)), "{err:?}");
    assert_eq!(status(&c), Some("in_review".into()));
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 1);
}

#[test]
fn a_write_inside_an_open_transaction_is_refused() {
    // in_tx owns its transaction; nesting would make the audit row commit separately from the change.
    let c = case_with_finding();
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    assert!(write::set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).is_err());
    c.conn().execute_batch("ROLLBACK").unwrap();
    assert_eq!(status(&c), Some("new".into()));
    assert!(audit::log(c.conn(), None).unwrap().is_empty());
}

// ---------------------------------------------------------------- review

#[test]
fn accept_marks_reviewed() {
    let c = case_with_finding();
    let d = write::set_finding_status(c.conn(), &agent(), "f1", S::Confirmed, Some("r")).unwrap();
    let r =
        review::review_accept(c.conn(), &carlos(), "finding", "f1", d.seq, Some("agree")).unwrap();
    assert_eq!(r.action, "review_accept");
    assert_eq!(r.actor, "analyst:carlos");
    assert_eq!(r.reason.as_deref(), Some("agree"));
    assert_eq!(review_state(&c), Some("accepted".into()));
    assert_eq!(
        col(&c, "SELECT reviewed_by FROM findings"),
        Some("analyst:carlos".into())
    );
    assert_eq!(
        col(&c, "SELECT review_comment FROM findings"),
        Some("agree".into())
    );
    assert_eq!(status(&c), Some("confirmed".into()));
    assert_eq!(
        col(&c, "SELECT decided_by FROM findings"),
        Some("agent:claude".into())
    );
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn discard_reverts_to_the_prior_state() {
    let c = case_with_finding();
    let d = write::set_finding_status(
        c.conn(),
        &agent(),
        "f1",
        S::FalsePositive,
        Some("looks benign"),
    )
    .unwrap();
    let r =
        review::review_discard(c.conn(), &carlos(), "finding", "f1", d.seq, Some("no")).unwrap();
    assert_eq!(r.action, "review_discard");
    assert_eq!(status(&c), Some("new".into()));
    assert_eq!(col(&c, "SELECT disposition_reason FROM findings"), None);
    assert_eq!(review_state(&c), Some("discarded".into()));
    // Who made the discarded decision stays visible.
    assert_eq!(
        col(&c, "SELECT decided_by FROM findings"),
        Some("agent:claude".into())
    );
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn discard_of_superseded_decision_is_stale() {
    let c = case_with_finding();
    let first =
        write::set_finding_status(c.conn(), &agent(), "f1", S::Confirmed, Some("a")).unwrap();
    write::set_finding_status(c.conn(), &agent(), "f1", S::FalsePositive, Some("b")).unwrap();
    let err =
        review::review_discard(c.conn(), &carlos(), "finding", "f1", first.seq, None).unwrap_err();
    assert!(err.to_string().contains("changed since"), "{err}");
    assert!(is_decision_error(&err));
    assert_eq!(status(&c), Some("false_positive".into()));
    assert_eq!(review_state(&c), Some("pending_review".into()));
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 2);
}

#[test]
fn a_new_decision_after_review_resets_to_pending() {
    let c = case_with_finding();
    let d = write::set_finding_status(c.conn(), &agent(), "f1", S::Confirmed, Some("a")).unwrap();
    review::review_accept(c.conn(), &carlos(), "finding", "f1", d.seq, None).unwrap();
    let other = Actor::agent("codex", None).unwrap();
    write::assign_finding(c.conn(), &other, "f1", "dana").unwrap();
    assert_eq!(review_state(&c), Some("pending_review".into()));
    assert_eq!(col(&c, "SELECT reviewed_by FROM findings"), None);
    assert_eq!(col(&c, "SELECT reviewed_at::VARCHAR FROM findings"), None);
    assert_eq!(
        col(&c, "SELECT decided_by FROM findings"),
        Some("agent:codex".into())
    );
    assert_eq!(col(&c, "SELECT on_behalf_of FROM findings"), None);
}

#[test]
fn review_transitions() {
    let c = case_with_finding();
    let d = write::set_finding_status(c.conn(), &agent(), "f1", S::Confirmed, Some("a")).unwrap();
    // pending -> accepted; accepting again is refused.
    review::review_accept(c.conn(), &carlos(), "finding", "f1", d.seq, None).unwrap();
    let err = review::review_accept(c.conn(), &carlos(), "finding", "f1", d.seq, None).unwrap_err();
    assert!(is_decision_error(&err), "{err:?}");
    // accepted -> discarded (the reviewer changed their mind).
    review::review_discard(c.conn(), &carlos(), "finding", "f1", d.seq, None).unwrap();
    assert_eq!(
        (status(&c), review_state(&c)),
        (Some("new".into()), Some("discarded".into()))
    );
    // discarded is final until a new decision: no accept, no second discard.
    let err = review::review_accept(c.conn(), &carlos(), "finding", "f1", d.seq, None).unwrap_err();
    assert!(is_decision_error(&err), "{err:?}");
    assert!(review::review_discard(c.conn(), &carlos(), "finding", "f1", d.seq, None).is_err());
    assert_eq!(
        (status(&c), review_state(&c)),
        (Some("new".into()), Some("discarded".into()))
    );
    let actions: Vec<String> = audit::log(c.conn(), None)
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert_eq!(actions, ["set_status", "review_accept", "review_discard"]);
    // A new decision makes it reviewable again.
    let d2 = write::set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).unwrap();
    assert_eq!(review_state(&c), Some("pending_review".into()));
    review::review_accept(c.conn(), &carlos(), "finding", "f1", d2.seq, None).unwrap();
    assert_eq!(review_state(&c), Some("accepted".into()));
    // pending -> discarded directly.
    let d3 = write::assign_finding(c.conn(), &agent(), "f1", "dana").unwrap();
    review::review_discard(c.conn(), &carlos(), "finding", "f1", d3.seq, None).unwrap();
    assert_eq!(col(&c, "SELECT assigned_to FROM findings"), None);
    assert_eq!(status(&c), Some("in_review".into()));
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn review_needs_a_decision_and_a_known_object_type() {
    let c = case_with_finding();
    assert!(is_decision_error(
        &review::review_accept(c.conn(), &carlos(), "finding", "f1", 1, None).unwrap_err()
    ));
    let d = write::set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).unwrap();
    assert!(review::review_accept(c.conn(), &carlos(), "mailbox", "f1", d.seq, None).is_err());
    assert!(review::review_accept(c.conn(), &carlos(), "finding", "f2", d.seq, None).is_err());
    assert_eq!(
        review::latest_decision_seq(c.conn(), "finding", "f1").unwrap(),
        Some(d.seq)
    );
    assert_eq!(
        review::latest_decision_seq(c.conn(), "finding", "f2").unwrap(),
        None
    );
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 1);
}

// ---------------------------------------------------------------- indicators

fn ioc_state(c: &Case, id: &str) -> (String, Option<String>, Option<String>, Option<String>, bool) {
    c.conn()
        .query_row(
            "SELECT CAST(verdict AS VARCHAR), decided_by, on_behalf_of, CAST(review_state AS VARCHAR), \
             removed_at IS NOT NULL FROM case_indicators WHERE indicator_id = ?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap()
}

#[test]
fn indicator_writes_are_audited_decisions() {
    let c = Case::in_memory().unwrap();
    let id = add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::Ip,
        "203.0.113.9",
        Verdict::Malicious,
        Some("c2"),
    )
    .unwrap();
    assert_eq!(
        ioc_state(&c, &id),
        (
            "malicious".into(),
            Some("agent:claude".into()),
            Some("analyst:carlos".into()),
            Some("pending_review".into()),
            false
        )
    );
    let log = audit::log(c.conn(), Some(("indicator", &id))).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action, "add_ioc");
    assert_eq!(log[0].before, None);
    assert_eq!(log[0].after.as_ref().unwrap()["value"], "203.0.113.9");
    assert_eq!(
        micros(&c, "SELECT epoch_us(decided_at) FROM case_indicators"),
        log[0].ts.timestamp_micros()
    );
    let e = set_verdict(c.conn(), &agent(), &id, Verdict::Suspicious, None).unwrap();
    assert_eq!(e.action, "set_ioc_verdict");
    assert_eq!(e.before.unwrap()["verdict"], "malicious");
    assert_eq!(ioc_state(&c, &id).0, "suspicious");
    // set_verdict without a note keeps it.
    assert_eq!(
        list_indicators(c.conn(), None, false).unwrap()[0]
            .note
            .as_deref(),
        Some("c2")
    );
    assert!(is_decision_error(
        &set_verdict(c.conn(), &agent(), "nope", Verdict::Benign, None).unwrap_err()
    ));
    assert!(remove_indicator(c.conn(), &agent(), &id).unwrap());
    assert!(ioc_state(&c, &id).4);
    assert_eq!(
        col(&c, "SELECT removed_by FROM case_indicators"),
        Some("agent:claude".into())
    );
    // Removing again changes nothing and records nothing; a removed indicator takes no verdict.
    assert!(!remove_indicator(c.conn(), &agent(), &id).unwrap());
    assert!(set_verdict(c.conn(), &agent(), &id, Verdict::Malicious, None).is_err());
    assert!(list_indicators(c.conn(), None, false).unwrap().is_empty());
    let all = list_indicators(c.conn(), None, true).unwrap();
    assert_eq!(all.len(), 1);
    assert!(all[0].removed_at.is_some());
    // Re-adding a removed indicator brings it back.
    let again = add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::Ip,
        "203.0.113.9",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    assert_eq!(again, id);
    assert!(!ioc_state(&c, &id).4);
    assert_eq!(col(&c, "SELECT removed_by FROM case_indicators"), None);
    let actions: Vec<String> = audit::log(c.conn(), Some(("indicator", &id)))
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert_eq!(
        actions,
        ["add_ioc", "set_ioc_verdict", "remove_ioc", "add_ioc"]
    );
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn discarding_indicator_decisions_reverts_them() {
    let c = Case::in_memory().unwrap();
    // Discarding the add of a new indicator removes it.
    let id = add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::Upn,
        "a@x.example",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    let d = review::latest_decision_seq(c.conn(), "indicator", &id)
        .unwrap()
        .unwrap();
    review::review_discard(c.conn(), &carlos(), "indicator", &id, d, None).unwrap();
    assert!(list_indicators(c.conn(), None, false).unwrap().is_empty());
    assert_eq!(
        col(&c, "SELECT removed_by FROM case_indicators"),
        Some("analyst:carlos".into())
    );
    assert_eq!(ioc_state(&c, &id).3, Some("discarded".into()));
    // Re-add, remove, then discard the removal: it is active again.
    add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::Upn,
        "a@x.example",
        Verdict::Suspicious,
        None,
    )
    .unwrap();
    assert!(remove_indicator(c.conn(), &agent(), &id).unwrap());
    let d = review::latest_decision_seq(c.conn(), "indicator", &id)
        .unwrap()
        .unwrap();
    review::review_discard(c.conn(), &carlos(), "indicator", &id, d, None).unwrap();
    let active = list_indicators(c.conn(), None, false).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].verdict, Verdict::Suspicious);
    // Discarding a verdict change restores the old verdict.
    let e = set_verdict(c.conn(), &agent(), &id, Verdict::Benign, Some("vendor")).unwrap();
    review::review_discard(c.conn(), &carlos(), "indicator", &id, e.seq, None).unwrap();
    let active = list_indicators(c.conn(), None, false).unwrap();
    assert_eq!(
        (active[0].verdict, active[0].note.as_deref()),
        (Verdict::Suspicious, None)
    );
    assert!(audit::verify(c.conn()).unwrap().ok);
}

// ---------------------------------------------------------------- detection

const T1: &str = "t1";

fn opts(day: u32) -> DetectOptions {
    DetectOptions {
        now: Some(Utc.with_ymd_and_hms(2026, 3, day, 12, 0, 0).unwrap()),
        ..DetectOptions::default()
    }
}

fn ioc_rule_set() -> RuleSet {
    let text = "id: SPW-T-010\ntitle: ioc\nversion: 1\nstatus: experimental\nseverity: medium\nanalyst_guidance: g\n\
                source: ual_events\nmatch:\n  client_ip: {in: \"@list:case_iocs.ip\"}\ngroup_by: [ip]\n\
                tests:\n  - name: p\n    records: []\n    expect_hits: 1\n  - name: n\n    records: []\n    expect_hits: 0\n";
    let rule: Rule = serde_norway::from_str(text).unwrap();
    let sha256 = rule_sha256(&rule, &BTreeMap::new(), &BTreeMap::new());
    RuleSet {
        rules: vec![LoadedRule {
            path: "test:SPW-T-010".into(),
            sha256,
            rule,
        }],
        lists: BTreeMap::new(),
        list_meta: BTreeMap::new(),
        warnings: vec![],
    }
}

/// A case with one tenant and two UAL rows, from 203.0.113.9 and 198.51.100.1.
fn ioc_case() -> Case {
    let case = Case::in_memory().unwrap();
    detect::insert_row(&case, "tenant", T1, json!({"tenant_key": T1}));
    detect::collection_of(&case, T1);
    detect::insert_ual(
        &case,
        T1,
        json!({"record_id": "00000000-0000-0000-0000-000000000001", "client_ip": "203.0.113.9"}),
    );
    detect::insert_ual(
        &case,
        T1,
        json!({"record_id": "00000000-0000-0000-0000-000000000002", "client_ip": "198.51.100.1"}),
    );
    case
}

fn count(c: &Case, sql: &str) -> i64 {
    c.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn soft_deleted_ioc_is_not_read_by_rules_and_agent_malicious_is() {
    let mut c = ioc_case();
    let set = ioc_rule_set();
    assert_eq!(run(&mut c, &set, &opts(2)).unwrap().rules[0].hits, 0);
    let id = add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::Ip,
        "203.0.113.9",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    let r = run(&mut c, &set, &opts(3)).unwrap();
    assert_eq!((r.rules[0].hits, r.findings_new), (1, 1));
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM finding_evidence WHERE record_key = '00000000-0000-0000-0000-000000000001'"
        ),
        1
    );
    assert!(remove_indicator(c.conn(), &agent(), &id).unwrap());
    assert!(list_indicators(c.conn(), None, false).unwrap().is_empty());
    // The removed row is still stored, but rules no longer read it.
    assert_eq!(count(&c, "SELECT count(*) FROM case_indicators"), 1);
    let r = run(&mut c, &set, &opts(4)).unwrap();
    assert_eq!((r.rules[0].hits, r.findings_new), (0, 0));
    assert_eq!(count(&c, "SELECT count(*) FROM findings"), 1);
}

#[test]
fn discard_reverts_only_what_the_decision_changed() {
    // set_status, then detection flags rule_updated, then discard: the status reverts and rule_updated stays.
    let mut c = ioc_case();
    let set = ioc_rule_set();
    add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::Ip,
        "203.0.113.9",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    run(&mut c, &set, &opts(2)).unwrap();
    let fid = col(&c, "SELECT finding_id FROM findings").unwrap();
    let d = write::set_finding_status(c.conn(), &agent(), &fid, S::Confirmed, Some("c2 traffic"))
        .unwrap();
    assert_eq!(d.before.as_ref().unwrap()["rule_updated"], false);
    // A second indicator changes what the rule reads: detection flags the finding.
    add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::Ip,
        "198.51.100.77",
        Verdict::Suspicious,
        None,
    )
    .unwrap();
    run(&mut c, &set, &opts(3)).unwrap();
    assert_eq!(
        col(&c, "SELECT CAST(rule_updated AS VARCHAR) FROM findings"),
        Some("true".into())
    );
    review::review_discard(c.conn(), &carlos(), "finding", &fid, d.seq, None).unwrap();
    assert_eq!(status(&c), Some("new".into()));
    assert_eq!(col(&c, "SELECT disposition_reason FROM findings"), None);
    assert_eq!(
        col(&c, "SELECT CAST(rule_updated AS VARCHAR) FROM findings"),
        Some("true".into()),
        "detection's later flag survives the discard"
    );
}

#[test]
fn detection_rerun_preserves_decision_and_review() {
    // Detected once already (the cached case: built-in rules at the collection time plus a day).
    let mut g = synth::builtin_detected("bec-aitm", sparrow_synth::options::PsEdition::Ps7);
    let set =
        sparrow_core::detect::load::load_rules(&sparrow_core::data::DataDirs::default()).unwrap();
    let now = g.manifest.collected_at + chrono::Duration::days(1);
    let c = &g.case;
    let fid: String = c
        .conn()
        .query_row(
            "SELECT finding_id FROM findings ORDER BY rule_id, finding_id LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let d =
        write::set_finding_status(c.conn(), &agent(), &fid, S::Confirmed, Some("AiTM")).unwrap();
    write::assign_finding(c.conn(), &agent(), &fid, "dana").unwrap();
    let last = review::latest_decision_seq(c.conn(), "finding", &fid)
        .unwrap()
        .unwrap();
    assert!(last > d.seq);
    review::review_accept(c.conn(), &carlos(), "finding", &fid, last, Some("ok")).unwrap();
    let snapshot = |c: &Case| -> Vec<Option<String>> {
        c.conn()
            .query_row(
                "SELECT CAST(status AS VARCHAR), disposition_reason, assigned_to, decided_by, \
                        CAST(epoch_us(decided_at) AS VARCHAR), on_behalf_of, CAST(review_state AS VARCHAR), reviewed_by, \
                        CAST(epoch_us(reviewed_at) AS VARCHAR), review_comment FROM findings WHERE finding_id = ?",
                [&fid],
                |r| (0..10).map(|i| r.get(i)).collect(),
            )
            .unwrap()
    };
    let before = snapshot(c);
    assert_eq!(before[0].as_deref(), Some("confirmed"));
    assert_eq!(before[6].as_deref(), Some("accepted"));
    let findings_before = count(c, "SELECT count(*) FROM findings");
    let later = DetectOptions {
        now: Some(now + chrono::Duration::days(1)),
        ..DetectOptions::default()
    };
    let r = run(&mut g.case, &set, &later).unwrap();
    assert!(r.rules.iter().any(|x| x.hits > 0), "the re-run must hit");
    let c = &g.case;
    assert_eq!(count(c, "SELECT count(*) FROM findings"), findings_before);
    assert_eq!(snapshot(c), before);
    // Detection appends no audit entry.
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 3);
    assert!(audit::verify(c.conn()).unwrap().ok);
}
