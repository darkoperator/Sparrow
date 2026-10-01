use sparrow_synth::profiles::{Delivery, audit_profile, licence_profile, licence_profiles};
use sparrow_synth::scenario::{At, Polarity, StoryKind, builtin_names, from_yaml, load};

const MINIMAL: &str = r#"
name: t
tenant: {name: T Example, domains: [t.example], users: 3, licence_profile: m365_e5}
window: {start: 2026-08-01T00:00:00Z, days: 10, collected_at: 2026-08-12T00:00:00Z}
storylines:
  - {kind: aitm_signin, id: s1, actor: 1, at: {day: 2, hour: 9}}
  - {kind: inbox_rule_finance, id: s2, actor: 1, at: {after: s1, minutes: 20}}
lookalikes:
  - {kind: vendor_filing_rule, id: l1, actor: 2, at: {day: 1, hour: 10, minute: 5}}
"#;

#[test]
fn builtins_load_and_validate() {
    assert_eq!(builtin_names().len(), 8);
    for name in builtin_names() {
        let s = load(name).unwrap();
        assert_eq!(&s.name, name);
    }
}

#[test]
fn minimal_scenario_parses_with_defaults() {
    let s = from_yaml(MINIMAL).unwrap();
    assert_eq!(s.tenant.admins, 1);
    assert_eq!(s.tenant.audit_profile, "default");
    assert_eq!(s.baseline.work_hours, (8, 18));
    assert!(matches!(s.storylines[1].at, At::After { .. }));
    let order: Vec<&str> = s
        .story_order()
        .unwrap()
        .iter()
        .map(|x| x.id.as_str())
        .collect();
    assert_eq!(order, ["l1", "s1", "s2"]);
    assert_eq!(StoryKind::AitmSignin.polarity(), Polarity::Positive);
    assert_eq!(StoryKind::VendorFilingRule.polarity(), Polarity::Lookalike);
}

#[test]
fn invalid_scenarios_are_rejected_with_the_field_named() {
    let cases = [
        (MINIMAL.replace("t.example", "t.com"), "domains"),
        (MINIMAL.replace("users: 3", "users: 1"), "users"),
        (MINIMAL.replace("days: 10", "days: 200"), "days"),
        (MINIMAL.replace("after: s1", "after: nope"), "after"),
        (MINIMAL.replace("actor: 2", "actor: 9"), "actor"),
        (
            MINIMAL.replace("kind: vendor_filing_rule", "kind: aitm_signin"),
            "lookalikes",
        ),
        (MINIMAL.replace("id: l1", "id: s1"), "id"),
        (MINIMAL.replace("m365_e5", "e9"), "licence_profile"),
        (MINIMAL.replace("name: t\n", "name: t\nbogus: 1\n"), "bogus"),
    ];
    for (yaml, needle) in cases {
        let err = from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains(needle), "{needle}: {err}");
    }
}

#[test]
fn licence_profile_expectations_are_hand_written() {
    assert_eq!(licence_profiles().len(), 6);
    let e5 = licence_profile("o365_e5").unwrap();
    assert!(e5.audit_premium() && e5.mdo_p2() && !e5.p1() && !e5.p2());
    let hawk = &e5.expect[&Delivery::Hawk4];
    assert_eq!(hawk["audit_premium"].status, "licensed");
    assert_eq!(hawk["audit_premium"].confidence.as_deref(), Some("low"));
    assert_eq!(hawk["identity_protection"].status, "unknown");
    assert_eq!(hawk["identity_protection"].confidence, None);
    let e3 = licence_profile("o365_e3").unwrap();
    assert!(
        e3.has_plan("atp_enterprise"),
        "trailing space and case are ignored"
    );
    assert_eq!(
        e3.expect[&Delivery::InvictusList]["mdo_p1"].status,
        "licensed"
    );
    for p in licence_profiles() {
        for d in [
            Delivery::InvictusList,
            Delivery::InvictusNoList,
            Delivery::Hawk4,
            Delivery::Hawk3,
            Delivery::Portal,
        ] {
            assert_eq!(p.expect[&d].len(), 11, "{} {d:?}", p.id);
        }
    }
    let a = audit_profile("customized_owner").unwrap();
    assert!(a.unified_audit_log_ingestion_enabled && !a.org_audit_disabled);
}
