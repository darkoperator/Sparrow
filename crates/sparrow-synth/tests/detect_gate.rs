//! The exact detection gate of `sparrow synth check` (Addendum C.3): sample rules pass on the
//! built-in scenarios, and each failure mode is caught.

use serde_json::json;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::coverage::BaselineAllow;
use sparrow_core::detect::load::{LoadedRule, RuleSet, load_rules, rule_sha256};
use sparrow_core::detect::rule::{Cond, Rule, RuleBody};
use sparrow_synth::cache::{Cache, CachedTree, Stage};
use sparrow_synth::check::{CheckReport, check, check_with, check_without_detection};
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::manifest::{Manifest, RuleExpect, RuleOutcome};
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::scenario::{At, Scenario, builtin_names, load};
use sparrow_synth::testing::detect_into;
use std::collections::BTreeMap;

static CACHE: std::sync::LazyLock<Cache> =
    std::sync::LazyLock::new(|| sparrow_synth::test_cache!());

/// A built-in scenario's tree (from the cross-binary test cache) with the means to get a private
/// copy of its ingested + profiled case, or that case after detection.
struct Tree {
    /// Keeps a private (uncached) tree alive under `SPARROW_NO_CACHE=1`.
    _cached: CachedTree,
    scenario: Scenario,
    opts: GenerateOptions,
}

impl Tree {
    fn profiled(&self) -> Case {
        CACHE
            .case(&self.scenario, &self.opts, Stage::Profiled)
            .unwrap_or_else(|e| panic!("cached case: {e}"))
            .case
    }

    /// Ingested, profiled and detected with the built-in rules.
    fn detected(&self) -> Case {
        CACHE
            .case(&self.scenario, &self.opts, Stage::Detected)
            .unwrap_or_else(|e| panic!("cached case: {e}"))
            .case
    }

    /// The profiled case with `set` run over it (a custom rule set).
    fn with_rules(&self, m: &Manifest, set: &RuleSet) -> Case {
        let mut case = self.profiled();
        detect_into(&mut case, m, set);
        case
    }
}

fn tree(name: &str, c: Collector) -> (Tree, Manifest) {
    let scenario = load(name).unwrap();
    let opts = GenerateOptions::new(c, 1);
    let cached = CACHE
        .tree(&scenario, &opts)
        .unwrap_or_else(|e| panic!("cached tree: {e}"));
    let m = cached.manifest.clone();
    (
        Tree {
            _cached: cached,
            scenario,
            opts,
        },
        m,
    )
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

/// The `baseline_allow` entries of `coverage.yaml`: the real exceptions apply next to a test's
/// own (every trigger record of a finding is checked against them).
fn coverage_allow() -> BTreeMap<String, Vec<BaselineAllow>> {
    sparrow_synth::coverage::rules()
        .iter()
        .filter(|r| !r.baseline_allow.is_empty())
        .map(|r| (r.id.clone(), r.baseline_allow.clone()))
        .collect()
}

fn gate(name: &str, c: Collector) -> (CheckReport, Manifest, Case) {
    let (dir, m) = tree(name, c);
    let case = dir.detected();
    let report = check(&m, &case).unwrap();
    (report, m, case)
}

fn assert_gate_ok(name: &str, c: Collector) -> CheckReport {
    let (r, ..) = gate(name, c);
    assert!(r.ok, "{name} {c:?}: {:#?}", r.problems);
    assert!(r.detection.skipped.is_none(), "{name} {c:?}");
    assert_eq!(
        r.detection.rules_checked,
        builtin_set().rules.len(),
        "{name} {c:?}: every loaded rule file was checked"
    );
    r
}

/// A password-spray tree with `hawk_users: [2, 3, 20]`: Hawk 4's per-user sign-ins cover 3 users, so
/// the spray rules, which need sign-ins of 5 distinct users, are recorded `not_applicable` in
/// `detection_runs` with the "fewer than the 5" reason, while the tenant-wide Portal export (all users)
/// runs them. Asserted on the stored detection runs, not on the gate's verdict.
#[test]
fn hawk4_records_the_spray_rules_as_not_applicable_in_a_password_spray_tree() {
    let runs = |c: Collector| -> Vec<(String, String, Option<String>)> {
        let (_, _, case) = gate("password-spray", c);
        let mut st = case
            .conn()
            .prepare(
                "SELECT rule_id, CAST(status AS VARCHAR), reason FROM detection_runs
                 WHERE rule_id IN ('SPW-ID-005', 'SPW-ID-006') ORDER BY rule_id",
            )
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let hawk4 = runs(Collector::Hawk4);
    assert_eq!(hawk4.len(), 2, "{hawk4:?}");
    for (rule, status, reason) in &hawk4 {
        assert_eq!(status, "not_applicable", "{rule}");
        let reason = reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("sign-ins cover 3 distinct users"),
            "{rule}: {reason}"
        );
        assert!(reason.contains("fewer than the 5"), "{rule}: {reason}");
    }
    let portal = runs(Collector::Portal);
    assert_eq!(portal.len(), 2, "{portal:?}");
    assert!(
        portal.iter().all(|(_, status, _)| status == "ran"),
        "{portal:?}"
    );
}

#[test]
fn gate_passes_for_the_sample_rules() {
    // bec-aitm exercises every sample rule and every collector; the full matrix is the ignored job.
    for c in Collector::ALL {
        let r = assert_gate_ok("bec-aitm", *c);
        assert_eq!(r.rules_unchecked, 0, "every seed rule has a rule file");
    }
}

/// The password-spray scenario carries the new-account sends of SPW-MAIL-006 (a hosting positive and
/// ordinary-ISP and new-office-address look-alikes in the first days of the window; no spray-source
/// positive, see coverage.yaml); the gate checks them exactly on every collector, without the full ignored
/// matrix.
#[test]
fn gate_passes_for_the_password_spray_scenario_on_every_collector() {
    for c in Collector::ALL {
        assert_gate_ok("password-spray", *c);
    }
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn gate_passes_for_the_sample_rules_on_every_scenario_and_collector() {
    // Every scenario and collector is checked and ALL failures are reported at once, and the
    // seed pack is complete on every one of them.
    let mut failed = Vec::new();
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            let (r, ..) = gate(name, *c);
            if r.rules_unchecked != 0 {
                failed.push(format!(
                    "{name} {c:?}: {} rule expectations have no rule file",
                    r.rules_unchecked
                ));
            }
            if !r.ok {
                failed.push(format!("{name} {c:?}: {:#?}", r.problems));
            }
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
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
    let case = dir.with_rules(&m, &set);
    let r = check_with(&m, &case, &set, &coverage_allow()).unwrap();
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
    let case = dir.with_rules(&m, &set);
    let r = check_with(&m, &case, &set, &coverage_allow()).unwrap();
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
    let case = dir.with_rules(&m, &set);
    // Allow the background logins and every storyline kind that also logs in.
    let mut kinds: Vec<String> = m.storylines.iter().map(|s| s.kind.clone()).collect();
    kinds.push("baseline".to_string());
    let mut allow = coverage_allow();
    allow.insert(
        "SPW-TEST-001".to_string(),
        kinds
            .into_iter()
            .map(|kind| BaselineAllow {
                kind,
                reason: "test: logins are ordinary activity".into(),
            })
            .collect::<Vec<_>>(),
    );
    let r = check_with(&m, &case, &set, &allow).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
    // A narrower allow-list still fails.
    let mut narrow = coverage_allow();
    narrow.insert(
        "SPW-TEST-001".to_string(),
        vec![BaselineAllow {
            kind: "baseline".into(),
            reason: "only background".into(),
        }],
    );
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
    let case = dir.detected();
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
    let r = check_with(&m, &case, &set, &coverage_allow()).unwrap();
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
    let case2 = dir2.detected();
    m2.rules.push(RuleExpect {
        rule_id: "SPW-HAWK-011".into(),
        storyline: "l-dismiss".into(),
        outcome: RuleOutcome::NotApplicable,
        reason: "unified audit log ingestion disabled".into(),
        tables: vec!["mailboxes".into()],
        complete: true,
        computed: None,
    });
    let r = check_with(&m2, &case2, &set, &coverage_allow()).unwrap();
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
    let case = dir.with_rules(&m, &set);
    let story = m.storylines[0].id.clone();
    m.rules.push(RuleExpect {
        rule_id: "SPW-TEST-002".into(),
        storyline: story.clone(),
        outcome: RuleOutcome::NotApplicable,
        reason: "capability identity_protection is not_licensed".into(),
        tables: vec!["risky_users".into()],
        complete: true,
        computed: None,
    });
    let cap = m
        .capabilities
        .get("identity_protection")
        .map(|c| c.status.clone());
    let r = check_with(&m, &case, &set, &coverage_allow()).unwrap();
    if cap.as_deref() == Some("not_licensed") {
        assert!(r.ok, "{:#?}", r.problems);
    }
    // Claiming not_applicable for a licensed tenant while the run log says `ran` is caught.
    let (dir2, mut m2) = tree("bec-aitm", Collector::Hawk4);
    let case2 = dir2.with_rules(&m2, &set);
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
        complete: true,
        computed: None,
    });
    let r = check_with(&m2, &case2, &set, &coverage_allow()).unwrap();
    assert!(
        r.detection
            .applicability
            .iter()
            .any(|p| p.starts_with("SPW-TEST-002") && p.contains("run log says ran")),
        "{:#?}",
        r.detection
    );
}

fn manifest_of(name: &str, c: Collector) -> Manifest {
    tree(name, c).1
}

/// The organization-level `audit_config` state row cannot identify a storyline: the benign
/// audit-config change (a look-alike of SPW-CFG-001) must not own the row the tamper sets.
#[test]
fn a_shared_org_state_row_belongs_to_no_lookalike() {
    for c in [Collector::Hawk4, Collector::Invictus] {
        let m = manifest_of("audit-tamper", c);
        let benign = m.storylines.iter().find(|s| s.id == "l-auditok").unwrap();
        assert!(
            benign.evidence.iter().all(|e| e.what != "AuditConfig"),
            "{c:?}: the benign change owns the shared audit_config row: {:?}",
            benign.evidence
        );
        let o = m
            .rules
            .iter()
            .find(|r| r.rule_id == "SPW-CFG-001" && r.storyline == "l-auditok");
        // Its own cmdlet records still make it a look-alike of the rule.
        assert!(
            o.is_some_and(|o| o.outcome == RuleOutcome::NoHit),
            "{c:?}: {o:?}"
        );
    }
}

/// Invictus's mailbox files carry no forwarding field, and the Set-Mailbox record falls in the
/// UAL-off window: nothing of the forwarding storyline landed, so the outcome is NoEvidence.
#[test]
fn forwarding_in_the_ual_off_window_has_no_evidence_on_invictus() {
    let inv = manifest_of("audit-tamper", Collector::Invictus);
    let o = inv
        .rules
        .iter()
        .find(|r| r.rule_id == "SPW-MAIL-004" && r.storyline == "s-fwd")
        .unwrap();
    assert_eq!(o.outcome, RuleOutcome::NoEvidence, "{o:?}");
    // A collector whose mailbox files carry the forwarding address still expects the hit.
    let h4 = manifest_of("audit-tamper", Collector::Hawk4);
    let o = h4
        .rules
        .iter()
        .find(|r| r.rule_id == "SPW-MAIL-004" && r.storyline == "s-fwd")
        .unwrap();
    assert_eq!(o.outcome, RuleOutcome::Hit, "{o:?}");
}

/// An ingest without detection reports a problem, not a silent pass; the explicit opt-out
/// `check_without_detection` is the only way to skip the gate.
#[test]
fn the_gate_fails_when_detection_did_not_run() {
    let (dir, m) = tree("bec-aitm", Collector::Hawk4);
    let case = dir.profiled();
    let r = check(&m, &case).unwrap();
    assert!(!r.ok);
    assert!(
        r.detection
            .applicability
            .iter()
            .any(|p| p.contains("no detection run")),
        "{:#?}",
        r.detection
    );
    assert_eq!(r.detection.rules_checked, 0);
    let r = check_without_detection(&m, &case).unwrap();
    assert!(r.ok, "{:#?}", r.problems);
    assert!(r.detection.skipped.is_some());
}

/// A partial run (a rule of the set missing from the latest run) fails the gate.
#[test]
fn the_gate_fails_on_a_partial_run() {
    let (dir, m) = tree("bec-aitm", Collector::Hawk4);
    let full = builtin_set();
    let mut partial = builtin_set();
    partial.rules.retain(|r| r.rule.id != "SPW-ID-010");
    let case = dir.with_rules(&m, &partial);
    let r = check_with(&m, &case, &full, &coverage_allow()).unwrap();
    assert!(!r.ok);
    assert!(
        r.detection
            .applicability
            .iter()
            .any(|p| p.starts_with("SPW-ID-010") && p.contains("partial run")),
        "{:#?}",
        r.detection
    );
    assert_eq!(r.detection.rules_checked, full.rules.len() - 1);
}

/// One finding that cites a hit storyline's record AND background records fails: every trigger
/// record is checked, not just one.
#[test]
fn a_finding_citing_hit_and_baseline_records_fails() {
    let (dir, mut m) = tree("bec-aitm", Collector::Hawk4);
    let mut set = builtin_set();
    every_login_rule(&mut set);
    let case = dir.with_rules(&m, &set);
    // Declare the AiTM storyline a hit of the custom rule: its login is one of the records the
    // (per-actor) finding cites, next to the background logins of the same user.
    m.rules.push(RuleExpect {
        rule_id: "SPW-TEST-001".into(),
        storyline: "s-aitm".into(),
        outcome: RuleOutcome::Hit,
        reason: "test".into(),
        tables: vec!["ual_events".into()],
        complete: true,
        computed: None,
    });
    let r = check_with(&m, &case, &set, &coverage_allow()).unwrap();
    assert!(
        r.detection
            .unexpected_hits
            .iter()
            .any(|p| p.starts_with("SPW-TEST-001") && p.contains("baseline")),
        "{:#?}",
        r.detection
    );
}

/// A correlated rule's storyline that lost a half is not complete: one delivered UAL record
/// cannot stand for both halves.
#[test]
fn a_correlated_storyline_with_a_lost_half_is_incomplete() {
    let mut sc = load("bec-aitm").unwrap();
    // The anonymous link of a user with no risky sign-in of its own storyline.
    sc.storylines
        .retain(|s| s.id == "s-aitm" || s.id == "s-anon");
    let anon = sc.storylines.iter_mut().find(|s| s.id == "s-anon").unwrap();
    anon.actor = Some(12);
    anon.at = At::Day {
        day: 20,
        hour: 12,
        minute: 0,
    };
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&sc, &GenerateOptions::new(Collector::Hawk4, 1), dir.path()).unwrap();
    let o = m
        .rules
        .iter()
        .find(|r| r.rule_id == "SPW-FILE-002" && r.storyline == "s-anon")
        .unwrap();
    assert_eq!(o.outcome, RuleOutcome::Hit);
    assert!(!o.complete, "{o:?}");
    // With the AiTM sign-in of the same user, the same storyline is complete.
    let full = manifest_of("bec-aitm", Collector::Hawk4);
    let o = full
        .rules
        .iter()
        .find(|r| r.rule_id == "SPW-FILE-002" && r.storyline == "s-anon")
        .unwrap();
    assert!(o.complete, "{o:?}");
}

/// Detection safety for **sign-in interrupts** (F10). An interrupt is an `UserLoginFailed` row
/// whose `ResultStatus` is `Success`: the audit log records the attempt that stopped at the MFA
/// or "Stay signed in?" prompt, and the user then completes the sign-in. It must never read as a
/// completed sign-in, and never as a burst of failures.
#[test]
fn a_sign_in_interrupt_never_reaches_a_finding() {
    for (name, c) in [
        ("bec-aitm", Collector::Hawk4),
        ("bec-aitm", Collector::Invictus),
    ] {
        let (dir, _) = tree(name, c);
        let case = dir.detected();
        let interrupts: i64 = case
            .conn()
            .query_row(
                "SELECT count(*) FROM ual_events WHERE operation = 'UserLoginFailed' \
                 AND CAST(result_status AS VARCHAR) = 'Success'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(interrupts > 0, "{name} {c:?}: no interrupts in the tree");

        // No finding's trigger evidence may cite one, and no rule may be `error`.
        let cited: i64 = case
            .conn()
            .query_row(
                "SELECT count(*) FROM finding_evidence e \
                 JOIN ual_events u ON lower(CAST(u.record_id AS VARCHAR)) = e.record_key \
                 JOIN findings f ON f.finding_id = e.finding_id \
                 WHERE e.source_table = 'ual_events' AND u.operation = 'UserLoginFailed' \
                   AND CAST(u.result_status AS VARCHAR) = 'Success'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            cited, 0,
            "{name} {c:?}: a finding cites a sign-in interrupt"
        );

        let errors: i64 = case
            .conn()
            .query_row(
                "SELECT count(*) FROM detection_runs WHERE CAST(status AS VARCHAR) = 'error'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(errors, 0, "{name} {c:?}: a rule failed");
    }
}

/// The same safety, stated over the rules themselves rather than over one tree: no built-in rule
/// may mention the `UserLoginFailed` operation, so an interrupt is invisible to every rule and
/// cannot be read as a completed sign-in or counted as a failure.
#[test]
fn no_built_in_rule_reads_a_failed_logon() {
    let set = builtin_set();
    assert!(set.rules.len() > 20, "{} rules", set.rules.len());
    for lr in &set.rules {
        // The whole rule, serialized, so a `match:` leaf cannot slip past a `sql:`-only check.
        let text = serde_json::to_string(&lr.rule).unwrap().to_lowercase();
        assert!(
            !text.contains("userloginfailed"),
            "{}: reads the UserLoginFailed operation",
            lr.rule.id
        );
    }
    // And the logon-reading rules name the completed operation, so their intent is explicit.
    let readers: Vec<&str> = set
        .rules
        .iter()
        .filter(|lr| {
            serde_json::to_string(&lr.rule)
                .unwrap()
                .to_lowercase()
                .contains("userloggedin")
        })
        .map(|lr| lr.rule.id.as_str())
        .collect();
    assert!(
        readers.contains(&"SPW-ID-002") && readers.contains(&"SPW-ID-003"),
        "the sign-in rules name UserLoggedIn: {readers:?}"
    );
}

/// The four correlation negatives deliver both evidence halves and must not fire their rule:
/// the manifest expects NoHit, the rule file exists, and the gate passes with them checked.
#[test]
fn gate_exercises_the_correlation_negatives() {
    const NEGATIVES: [(&str, &str); 4] = [
        ("l-cn-mfa", "SPW-ID-001"),
        ("l-cn-rule", "SPW-ID-010"),
        ("l-cn-anon", "SPW-FILE-002"),
        ("l-cn-lure", "SPW-FILE-003"),
    ];
    let (report, m, _case) = gate("bec-aitm", Collector::Invictus);
    assert!(report.ok, "{:#?}", report.problems);
    let set = builtin_set();
    for (story, rule) in NEGATIVES {
        assert!(
            set.rules.iter().any(|r| r.rule.id == rule),
            "{rule} has a rule file"
        );
        assert!(
            m.rules.iter().any(|r| r.rule_id == rule
                && r.storyline == story
                && r.outcome == RuleOutcome::NoHit),
            "{story} is a NoHit for {rule}"
        );
    }
}

/// What landed decides the outcome: in audit-tamper the surviving collected rule of the admin's
/// storyline is the forwarding "Sync" rule (no finance words, no hiding folder) and the cmdlet
/// that made the qualifying rule fell in the audit-off window, so SPW-MAIL-003 has no evidence;
/// where the cmdlets are logged (hawk-investigate) it still expects the hit.
#[test]
fn a_collected_rule_that_does_not_meet_the_rule_is_no_evidence() {
    for c in [Collector::Hawk3, Collector::Hawk4, Collector::Invictus] {
        let m = manifest_of("audit-tamper", c);
        let o = m
            .rules
            .iter()
            .find(|r| r.rule_id == "SPW-MAIL-003" && r.storyline == "s-admrule")
            .unwrap();
        assert_eq!(o.outcome, RuleOutcome::NoEvidence, "{c:?}: {o:?}");
    }
    let m = manifest_of("hawk-investigate", Collector::Hawk4);
    let o = m
        .rules
        .iter()
        .find(|r| r.rule_id == "SPW-MAIL-003" && r.storyline == "s-admrule")
        .unwrap();
    assert_eq!(o.outcome, RuleOutcome::Hit, "{o:?}");
}

/// A scenario whose audit profile leaves organization auditing off owns the collected
/// `audit_config` row through an explicit state storyline, and SPW-CFG-001 must hit it.
#[test]
fn an_org_audit_disabled_profile_is_an_explicit_cfg_hit() {
    for c in [Collector::Hawk3, Collector::Hawk4, Collector::Invictus] {
        let (r, m, _case) = gate("business-basic", c);
        assert!(r.ok, "{c:?}: {:#?}", r.problems);
        let o = m
            .rules
            .iter()
            .find(|r| r.rule_id == "SPW-CFG-001" && r.storyline == "s-orgaudit")
            .unwrap_or_else(|| panic!("{c:?}: no expectation for the state storyline"));
        assert_eq!(o.outcome, RuleOutcome::Hit, "{c:?}: {o:?}");
    }
}

/// The correlated half comes from the storyline itself or one it is anchored after: an
/// unrelated storyline of the same user (here an AiTM sign-in anchored by day, not `after`) does
/// not complete it.
#[test]
fn only_a_storyline_it_follows_supplies_the_missing_half() {
    let complete = |anchored: bool| {
        let mut sc = load("bec-aitm").unwrap();
        sc.storylines
            .retain(|s| s.id == "s-aitm" || s.id == "s-mfa");
        if !anchored {
            let mfa = sc.storylines.iter_mut().find(|s| s.id == "s-mfa").unwrap();
            mfa.at = At::Day {
                day: 20,
                hour: 12,
                minute: 0,
            };
        }
        let dir = tempfile::tempdir().unwrap();
        let m =
            generate_to_dir(&sc, &GenerateOptions::new(Collector::Hawk4, 1), dir.path()).unwrap();
        m.rules
            .iter()
            .find(|r| r.rule_id == "SPW-ID-001" && r.storyline == "s-mfa")
            .unwrap()
            .complete
    };
    assert!(complete(true), "anchored after the AiTM sign-in");
    assert!(!complete(false), "same user, but not anchored to it");
}
