use sparrow_synth::expect::{capabilities, delivery};
use sparrow_synth::geo::geo_entries;
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::profiles::Delivery;
use sparrow_synth::scenario::load;
use sparrow_synth::story::apply;
use sparrow_synth::world::World;

#[test]
fn deliveries_follow_the_collector() {
    assert_eq!(
        delivery(&GenerateOptions::new(Collector::Hawk4, 1), true),
        Delivery::Hawk4
    );
    assert_eq!(
        delivery(&GenerateOptions::new(Collector::Invictus, 1), true),
        Delivery::InvictusList
    );
    assert_eq!(
        delivery(&GenerateOptions::new(Collector::Invictus, 1), false),
        Delivery::InvictusNoList
    );
    let mut o = GenerateOptions::new(Collector::Invictus, 1);
    o.invictus_licence_list = false;
    assert_eq!(delivery(&o, true), Delivery::InvictusNoList);
}

#[test]
fn capability_expectations_come_from_the_profile_table() {
    let w = World::build(&load("hawk-investigate").unwrap(), 1).unwrap();
    let caps = capabilities(&w, Delivery::Hawk4);
    assert_eq!(caps["audit_premium"].status, "licensed");
    assert_eq!(caps["identity_protection"].status, "unknown");
}

#[test]
fn geo_covers_every_ip_in_the_world() {
    let mut w = World::build(&load("bec-aitm").unwrap(), 1).unwrap();
    apply(&mut w).unwrap();
    let (city, asn) = geo_entries(&w);
    let ips: std::collections::BTreeSet<_> = asn.iter().map(|(ip, _, _)| *ip).collect();
    assert!(ips.contains(&w.attacker.proxy_ip) && ips.contains(&w.attacker.replay_ip));
    for u in w.all_people() {
        assert!(ips.contains(&u.office_ip) && ips.contains(&u.home_ip));
    }
    assert_eq!(city.len(), asn.len());
}

#[test]
fn record_types_match_sparrows_table() {
    use sparrow_synth::events::RecordType;
    for rt in RecordType::ALL {
        let found = sparrow_core::normalize::record_types::RECORD_TYPES
            .iter()
            .find(|(n, _)| *n == rt.number());
        assert_eq!(found.map(|(_, name)| *name), Some(rt.name()), "{rt:?}");
    }
}

use sparrow_synth::expect::{evidence, rule_outcomes};
use sparrow_synth::manifest::RuleOutcome;
use sparrow_synth::ps::Encoding;
use sparrow_synth::story::Evidence;
use sparrow_synth::tree::{CulturePolicy, FileSpec, MemSink, Tree, TreeOutcome};
use std::collections::BTreeSet;

fn outcome_of(
    rules: &[sparrow_synth::manifest::RuleExpect],
    rule: &str,
    story: &str,
) -> (RuleOutcome, String) {
    let r = rules
        .iter()
        .find(|r| r.rule_id == rule && r.storyline == story)
        .unwrap_or_else(|| panic!("{rule} {story}"));
    (r.outcome, r.reason.clone())
}

/// A Hawk tree whose one parsed file delivers every logged UAL record of the storylines.
fn ual_tree(w: &World, records: &[sparrow_synth::story::StoryRecord]) -> TreeOutcome {
    let tracked: BTreeSet<Evidence> = records.iter().flat_map(|r| r.evidence.clone()).collect();
    let mut sink = MemSink::default();
    let mut t = Tree::new(&mut sink, "R", tracked, CulturePolicy::Never);
    let spec = FileSpec::new(
        "Tenant/All.json",
        Some("hawk.tenant.raw_ual"),
        Encoding::Utf8,
    );
    t.write(&spec, "[\r\n").unwrap();
    for u in w.story.ual.iter().filter(|u| w.logged(u)) {
        let line = t.write(&spec, "{}\r\n").unwrap() + 1;
        t.row(&spec.rel, "ual_events", sparrow_synth::keys::ual(u.id));
        t.deliver(&Evidence::Ual(u.id), "ual_events", &spec.rel, (line, line));
    }
    t.write(&spec, "]\r\n").unwrap();
    t.finish().unwrap()
}

#[test]
fn rule_outcomes_follow_licences_audit_settings_and_deliveries() {
    let mut w = World::build(&load("bec-e3-audit-gaps").unwrap(), 1).unwrap();
    let records = apply(&mut w).unwrap();
    let opts = GenerateOptions::new(Collector::Hawk4, 1);
    let caps = capabilities(&w, delivery(&opts, false));
    let out = ual_tree(&w, &records);
    let rules = rule_outcomes(&w, &records, &caps, &out);
    let (o, why) = outcome_of(&rules, "SPW-HAWK-008", "s-aitm");
    assert_eq!(o, RuleOutcome::NotApplicable);
    assert!(why.contains("identity_protection"), "{why}");
    // customized_owner drops MailItemsAccessed from the owner list.
    assert_eq!(
        outcome_of(&rules, "SPW-MAIL-005", "s-mia"),
        (
            RuleOutcome::NotApplicable,
            "action not in the mailbox's audit list".into()
        )
    );
    assert_eq!(
        outcome_of(&rules, "SPW-MAIL-003", "s-rule").0,
        RuleOutcome::Hit
    );
    assert_eq!(
        outcome_of(&rules, "SPW-MAIL-003", "l-vendor").0,
        RuleOutcome::NoHit
    );
    // The tree has no mailboxes file.
    let (o, why) = outcome_of(&rules, "SPW-HAWK-011", "s-fwd");
    assert_eq!(o, RuleOutcome::NoEvidence);
    assert!(why.starts_with("Hawk "), "{why}");
}

#[test]
fn evidence_expectations() {
    let mut w = World::build(&load("bec-e3-audit-gaps").unwrap(), 1).unwrap();
    let records = apply(&mut w).unwrap();
    let out = ual_tree(&w, &records);
    let e = evidence(&w, &GenerateOptions::new(Collector::Hawk4, 1), &out);
    assert_eq!(e["ual"].allowed, vec!["partial"]);
    assert_eq!(e["signins"].allowed, vec!["collected"]);
    assert_eq!(e["risk_detections"].allowed, vec!["not_licensed"]);
    assert!(
        !e.contains_key("licenses"),
        "the licence list is not parsed yet"
    );
    let e = evidence(&w, &GenerateOptions::new(Collector::Invictus, 1), &out);
    assert_eq!(e["ual"].allowed, vec!["collected"]);
}

#[test]
fn why_not_logged_names_the_setting() {
    let mut w = World::build(&load("audit-tamper").unwrap(), 1).unwrap();
    apply(&mut w).unwrap();
    let reasons: BTreeSet<&str> = w
        .story
        .ual
        .iter()
        .filter_map(|u| w.why_not_logged(u))
        .collect();
    for r in &reasons {
        assert!(
            [
                "unified audit log ingestion disabled",
                "mailbox auditing disabled for the organization",
                "mailbox audit bypass",
                "mailbox auditing disabled for the mailbox",
                "action not in the mailbox's audit list",
            ]
            .contains(r),
            "{r}"
        );
    }
    assert!(
        w.story
            .ual
            .iter()
            .all(|u| w.logged(u) == w.why_not_logged(u).is_none())
    );
}
