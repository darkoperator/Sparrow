use sparrow_synth::coverage::{evidence_all_of_satisfied, report};
use sparrow_synth::options::Collector;

#[test]
fn coverage_has_no_gaps() {
    let r = report(1).unwrap();
    assert_eq!(r.rules.len(), 34);
    assert!(r.ok, "{}", r.gaps.join("\n"));
}

#[test]
fn the_report_names_collectors_and_profiles() {
    let r = report(1).unwrap();
    let aitm = r.rules.iter().find(|x| x.id == "SPW-ID-004").unwrap();
    for c in Collector::ALL {
        assert!(aitm.collectors_hit.contains(c), "{c:?}");
    }
    let risky = r.rules.iter().find(|x| x.id == "SPW-HAWK-012").unwrap();
    assert!(
        risky
            .not_applicable
            .iter()
            .any(|e| e.licence_profile == "m365_e3")
    );
    let text = r.to_text();
    assert!(text.contains("SPW-MAIL-003") && text.contains("look-alike:"));
}

/// A correlated rule counts a storyline as a hit/no_hit only when its evidence reaches every
/// half; SPW-ID-010's inbox-rule half (an admin-audit row for Hawk 3) alone is not a hit.
#[test]
fn a_correlated_rule_needs_every_evidence_half() {
    let groups = vec![
        vec!["ual_events".to_string(), "admin_audit_events".to_string()],
        vec!["signins".to_string(), "ual_events".to_string()],
    ];
    assert!(!evidence_all_of_satisfied(
        &groups,
        &["admin_audit_events".to_string()]
    ));
    // The preceding sign-in's UAL row completes the correlation.
    assert!(evidence_all_of_satisfied(
        &groups,
        &["admin_audit_events".to_string(), "ual_events".to_string()]
    ));
    // A rule with no groups has one group equal to its tables.
    assert!(evidence_all_of_satisfied(
        &[vec!["inbox_rules".to_string()]],
        &["inbox_rules".to_string()]
    ));
    assert!(!evidence_all_of_satisfied(
        &[vec!["inbox_rules".to_string()]],
        &["ual_events".to_string()]
    ));
}
