//! The exact detection gate of `sparrow synth check` (Addendum C.3): sample rules pass on the
//! built-in scenarios, and each failure mode is caught.

use serde_json::json;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::coverage::BaselineAllow;
use sparrow_core::detect::load::{LoadedRule, RuleSet, load_rules, rule_sha256};
use sparrow_core::detect::rule::{Cond, Rule, RuleBody};
use sparrow_synth::check::{CheckReport, check, check_with};
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::manifest::{Manifest, RuleExpect, RuleOutcome};
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::testing::{ingest_generated_detected, ingest_generated_with_rules};
use std::collections::BTreeMap;

const SAMPLE: [&str; 3] = ["SPW-HAWK-011", "SPW-ID-010", "SPW-MAIL-005"];

fn tree(name: &str, c: Collector) -> (tempfile::TempDir, Manifest) {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(
        &load(name).unwrap(),
        &GenerateOptions::new(c, 1),
        dir.path(),
    )
    .unwrap();
    (dir, m)
}

fn builtin_set() -> RuleSet {
    load_rules(&DataDirs::default()).unwrap()
}

fn custom_rule(set: &mut RuleSet, id: &str, body: &str) {
    let text = format!(
        "id: {id}\ntitle: custom {id}\nversion: 1\nstatus: experimental\nseverity: low\nanalyst_guidance: g\n{body}\ntests:\n  - name: p\n    records: []\n    expect_hits: 1\n  - name: n\n    records: []\n    expect_hits: 0\n"
    );
    let rule: Rule = serde_norway::from_str(&text).unwrap();
    let sha256 = rule_sha256(&rule, &set.lists, &set.list_meta);
    set.rules.retain(|r| r.rule.id != id);
    set.rules.push(LoadedRule {
        rule,
        path: format!("test:{id}"),
        sha256,
    });
    set.rules.sort_by(|a, b| a.rule.id.cmp(&b.rule.id));
}

fn gate(name: &str, c: Collector) -> (CheckReport, Manifest, Case) {
    let (dir, m) = tree(name, c);
    let case = ingest_generated_detected(dir.path(), &m);
    let report = check(&m, &case).unwrap();
    (report, m, case)
}

fn assert_gate_ok(name: &str, c: Collector) -> CheckReport {
    let (r, ..) = gate(name, c);
    assert!(r.ok, "{name} {c:?}: {:#?}", r.problems);
    assert!(r.detection.skipped.is_none(), "{name} {c:?}");
    assert!(
        r.detection.rules_checked >= SAMPLE.len(),
        "{name} {c:?}: {}",
        r.detection.rules_checked
    );
    r
}

#[test]
fn gate_passes_for_the_sample_rules() {
    // bec-aitm exercises every sample rule and every collector; the full matrix is the ignored job.
    for c in Collector::ALL {
        let r = assert_gate_ok("bec-aitm", *c);
        assert!(r.rules_unchecked > 0, "rules without a file are reported");
    }
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn gate_passes_for_the_sample_rules_on_every_scenario_and_collector() {
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            assert_gate_ok(name, *c);
        }
    }
}

#[test]
fn gate_catches_a_missing_hit() {
    let (dir, m) = tree("bec-aitm", Collector::Hawk4);
    let mut set = builtin_set();
    // SPW-HAWK-011 that matches nothing: the forwarding storyline is no longer detected.
    let lr = set
        .rules
        .iter_mut()
        .find(|r| r.rule.id == "SPW-HAWK-011")
        .unwrap();
    lr.rule.body = RuleBody::Match {
        source: "mailboxes".into(),
        m: Cond::from_json(
            &json!({"forwarding_smtp_address": {"eq": "no-such-address"}}),
            "match",
        )
        .unwrap(),
    };
    let case = ingest_generated_with_rules(dir.path(), &m, &set);
    let r = check_with(&m, &case, &set, &BTreeMap::new()).unwrap();
    assert!(!r.ok);
    assert!(
        r.detection
            .missing_hits
            .iter()
            .any(|p| p.starts_with("SPW-HAWK-011") && p.contains("forwarding_mailbox")),
        "{:#?}",
        r.detection
    );
    assert!(r.detection.unexpected_hits.is_empty(), "{:#?}", r.detection);
}

/// A custom rule that fires on every `UserLoggedIn` UAL record (the baseline has many).
fn every_login_rule(set: &mut RuleSet) {
    custom_rule(
        set,
        "SPW-TEST-001",
        "source: ual_events\nmatch:\n  operation: {eq: UserLoggedIn}",
    );
}

#[test]
fn gate_catches_an_unexpected_baseline_hit() {
    let (dir, m) = tree("bec-aitm", Collector::Hawk4);
    let mut set = builtin_set();
    every_login_rule(&mut set);
    let case = ingest_generated_with_rules(dir.path(), &m, &set);
    let r = check_with(&m, &case, &set, &BTreeMap::new()).unwrap();
    assert!(!r.ok);
    assert!(
        r.detection
            .unexpected_hits
            .iter()
            .any(|p| p.starts_with("SPW-TEST-001") && p.contains("baseline")),
        "{:#?}",
        r.detection
    );
    // The sample rules are unaffected.
    assert!(r.detection.missing_hits.is_empty(), "{:#?}", r.detection);
}

#[test]
fn baseline_allow_accepts_a_documented_exception() {
    let (dir, m) = tree("bec-aitm", Collector::Hawk4);
    let mut set = builtin_set();
    every_login_rule(&mut set);
    let case = ingest_generated_with_rules(dir.path(), &m, &set);
    // Allow the background logins and every storyline kind that also logs in.
    let mut kinds: Vec<String> = m.storylines.iter().map(|s| s.kind.clone()).collect();
    kinds.push("baseline".to_string());
    let allow = BTreeMap::from([(
        "SPW-TEST-001".to_string(),
        kinds
            .into_iter()
            .map(|kind| BaselineAllow {
                kind,
                reason: "test: logins are ordinary activity".into(),
            })
            .collect::<Vec<_>>(),
    )]);
    let r = check_with(&m, &case, &set, &allow).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
    // A narrower allow-list still fails.
    let narrow = BTreeMap::from([(
        "SPW-TEST-001".to_string(),
        vec![BaselineAllow {
            kind: "baseline".into(),
            reason: "only background".into(),
        }],
    )]);
    assert!(!check_with(&m, &case, &set, &narrow).unwrap().ok);
}

#[test]
fn correlation_negatives_do_not_fire() {
    // SPW-ID-010: both evidence halves exist, the risky sign-in is three hours too early.
    for c in [Collector::Hawk4, Collector::Invictus, Collector::Portal] {
        let (r, m, case) = gate("bec-aitm", c);
        assert!(r.ok, "{c:?}: {:#?}", r.problems);
        let ex = m
            .rules
            .iter()
            .find(|x| x.rule_id == "SPW-ID-010" && x.storyline == "l-cn-rule")
            .unwrap_or_else(|| panic!("{c:?}: no expectation for the correlation negative"));
        assert_eq!(ex.outcome, RuleOutcome::NoHit, "{c:?}: {}", ex.reason);
        // The positive still hits, and the negative's rule creation is not in any finding.
        let n: i64 = case
            .conn()
            .query_row(
                "SELECT count(*) FROM findings WHERE rule_id = 'SPW-ID-010'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(n >= 1, "{c:?}: the positive storyline must hit");
    }
}

#[test]
fn coverage_reports_a_correlated_rule_without_negative() {
    let mut rules: Vec<_> = sparrow_synth::coverage::rules().to_vec();
    let base = sparrow_synth::coverage::report_with(1, &rules).unwrap();
    assert!(base.gaps.is_empty(), "{:#?}", base.gaps);
    rules
        .iter_mut()
        .find(|r| r.id == "SPW-ID-010")
        .unwrap()
        .correlation_negatives
        .clear();
    let report = sparrow_synth::coverage::report_with(1, &rules).unwrap();
    assert!(
        report
            .gaps
            .iter()
            .any(|g| g == "SPW-ID-010: correlated rule has no correlation negative"),
        "{:#?}",
        report.gaps
    );
    // Every evidence_all_of rule in the file declares a negative that is also a look-alike.
    for r in sparrow_synth::coverage::rules()
        .iter()
        .filter(|r| r.evidence_all_of.len() > 1)
    {
        assert!(!r.correlation_negatives.is_empty(), "{}", r.id);
        for n in &r.correlation_negatives {
            assert!(r.lookalikes.contains(n), "{} {}", r.id, n.as_str());
        }
    }
}

/// An expectation only a logging gap explains is not the runner's tenant-wide `not_applicable`.
#[test]
fn a_gap_not_applicable_is_checked_as_no_finding() {
    let (dir, mut m) = tree("bec-aitm", Collector::Hawk4);
    let set = builtin_set();
    let case = ingest_generated_detected(dir.path(), &m);
    let fwd = m
        .rules
        .iter()
        .find(|x| x.rule_id == "SPW-HAWK-011" && x.outcome == RuleOutcome::Hit)
        .unwrap()
        .clone();
    // The oracle says the forwarding change fell in a logging gap, yet the rule found it.
    for x in m
        .rules
        .iter_mut()
        .filter(|x| x.rule_id == fwd.rule_id && x.storyline == fwd.storyline)
    {
        x.outcome = RuleOutcome::NotApplicable;
        x.reason = "unified audit log ingestion disabled".to_string();
    }
    let r = check_with(&m, &case, &set, &BTreeMap::new()).unwrap();
    assert!(!r.ok);
    assert!(
        r.detection
            .unexpected_hits
            .iter()
            .any(|p| p.contains("not applicable") && p.contains(&fwd.storyline)),
        "{:#?}",
        r.detection
    );
    // Without a finding on its records the same expectation passes (like NoEvidence).
    let (dir2, mut m2) = tree("bec-aitm", Collector::Hawk4);
    let case2 = ingest_generated_detected(dir2.path(), &m2);
    m2.rules.push(RuleExpect {
        rule_id: "SPW-HAWK-011".into(),
        storyline: "l-dismiss".into(),
        outcome: RuleOutcome::NotApplicable,
        reason: "unified audit log ingestion disabled".into(),
        tables: vec!["mailboxes".into()],
    });
    let r = check_with(&m2, &case2, &set, &BTreeMap::new()).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
}

/// A tenant-wide `not_applicable` must show in the run log.
#[test]
fn a_tenant_wide_not_applicable_must_be_in_the_run_log() {
    let (dir, mut m) = tree("business-basic", Collector::Hawk4);
    let mut set = builtin_set();
    custom_rule(
        &mut set,
        "SPW-TEST-002",
        "requires: [identity_protection]\nsource: risky_users\nmatch:\n  risk_level: {exists: true}",
    );
    let case = ingest_generated_with_rules(dir.path(), &m, &set);
    let story = m.storylines[0].id.clone();
    m.rules.push(RuleExpect {
        rule_id: "SPW-TEST-002".into(),
        storyline: story.clone(),
        outcome: RuleOutcome::NotApplicable,
        reason: "capability identity_protection is not_licensed".into(),
        tables: vec!["risky_users".into()],
    });
    let cap = m
        .capabilities
        .get("identity_protection")
        .map(|c| c.status.clone());
    let r = check_with(&m, &case, &set, &BTreeMap::new()).unwrap();
    if cap.as_deref() == Some("not_licensed") {
        assert!(r.ok, "{:#?}", r.problems);
    }
    // Claiming not_applicable for a licensed tenant while the run log says `ran` is caught.
    let (dir2, mut m2) = tree("bec-aitm", Collector::Hawk4);
    let case2 = ingest_generated_with_rules(dir2.path(), &m2, &set);
    m2.capabilities
        .get_mut("identity_protection")
        .unwrap()
        .status = "not_licensed".to_string();
    m2.rules.push(RuleExpect {
        rule_id: "SPW-TEST-002".into(),
        storyline: m2.storylines[0].id.clone(),
        outcome: RuleOutcome::NotApplicable,
        reason: "capability identity_protection is not_licensed".into(),
        tables: vec!["risky_users".into()],
    });
    let r = check_with(&m2, &case2, &set, &BTreeMap::new()).unwrap();
    assert!(
        r.detection
            .applicability
            .iter()
            .any(|p| p.starts_with("SPW-TEST-002") && p.contains("run log says ran")),
        "{:#?}",
        r.detection
    );
}
