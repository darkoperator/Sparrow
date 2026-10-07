//! The account roll-up expectations of the manifest (`expect::account_expectations`): which accounts the
//! roll-up must list after detection, with which stages and which `acts_without_signin` addresses, computed from
//! hand-built storylines, rule outcomes and record authors here, and from generated facts in `detect_gate.rs`.

use sparrow_synth::expect::{AccountFacts, account_expectations};
use sparrow_synth::manifest::{
    AccountExpect, EvidenceRef, Landed, RuleExpect, RuleOutcome, Sighting, StoryExpect,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

fn landed(table: &str, key: &str) -> Landed {
    Landed {
        table: table.into(),
        record_key: Some(key.into()),
        sighting: Sighting {
            rel_path: "f.csv".into(),
            line_start: 2,
            line_end: 2,
        },
    }
}

/// A storyline whose evidence delivered the records `(table, key)`.
fn story(id: &str, polarity: &str, actor: &str, records: &[(&str, &str)]) -> StoryExpect {
    StoryExpect {
        id: id.into(),
        kind: "k".into(),
        polarity: polarity.into(),
        actor: actor.into(),
        time: chrono::DateTime::from_timestamp(0, 0).unwrap(),
        evidence: vec![EvidenceRef {
            what: "x".into(),
            logged: true,
            delivered: records.iter().map(|(t, k)| landed(t, k)).collect(),
        }],
    }
}

fn rule(id: &str, storyline: &str, outcome: RuleOutcome, tables: &[&str]) -> RuleExpect {
    RuleExpect {
        rule_id: id.into(),
        storyline: storyline.into(),
        outcome,
        reason: String::new(),
        tables: tables.iter().map(|t| t.to_string()).collect(),
        complete: true,
        computed: None,
    }
}

fn stages() -> BTreeMap<String, Vec<String>> {
    [
        ("R-PERSIST", vec!["persistence"]),
        ("R-SIGNIN", vec!["suspicious_sign_in"]),
        ("R-BOTH", vec!["suspicious_sign_in", "persistence"]),
        ("R-NONE", vec![]),
        ("R-MAIL", vec!["mail_access"]),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.into_iter().map(String::from).collect()))
    .collect()
}

/// Who authored each `(table, key)` of these tests.
fn author(table: &str, key: &str) -> Option<String> {
    match (table, key) {
        ("ual_events", "m1" | "m2" | "u1" | "u2") => Some("alice@contoso.example".into()),
        ("ual_events", "m7" | "u7") => Some("bob@contoso.example".into()),
        ("signins", "s1") => Some("carol@contoso.example".into()),
        // An admin's cmdlet: the admin authored it, not the mailbox's owner.
        ("admin_audit_events", "a1") => Some("admin@contoso.example".into()),
        _ => None,
    }
}

type Unseen = BTreeMap<String, BTreeSet<IpAddr>>;

fn run(
    stories: &[StoryExpect],
    rules: &[RuleExpect],
) -> (Vec<AccountExpect>, Vec<BTreeSet<String>>) {
    let asked = std::cell::RefCell::new(Vec::new());
    let out = account_expectations(
        stories,
        rules,
        &stages(),
        &mut AccountFacts {
            author: &author,
            unseen: &mut |keys| {
                asked.borrow_mut().push(keys.clone());
                // The facts: alice reads from 198.51.100.9 (never signs in from it) in record m1.
                let mut u: Unseen = BTreeMap::new();
                if keys.contains("m1") {
                    u.entry("alice@contoso.example".into())
                        .or_default()
                        .insert("198.51.100.9".parse().unwrap());
                }
                Ok(u)
            },
        },
    )
    .unwrap();
    (out, asked.into_inner())
}

fn set(k: &[&str]) -> BTreeSet<String> {
    k.iter().map(|s| s.to_string()).collect()
}

#[test]
fn an_account_is_expected_when_a_rule_hits_a_record_the_actor_authored() {
    let stories = [
        story(
            "s-a",
            "positive",
            "Alice@Contoso.Example",
            &[("ual_events", "u1")],
        ),
        // A look-alike and a positive without a hit: neither expects an account.
        story(
            "l-b",
            "lookalike",
            "bob@contoso.example",
            &[("ual_events", "u7")],
        ),
        story(
            "s-c",
            "positive",
            "carol@contoso.example",
            &[("signins", "s1")],
        ),
    ];
    let rules = [
        rule("R-PERSIST", "s-a", RuleOutcome::Hit, &["ual_events"]),
        rule("R-PERSIST", "l-b", RuleOutcome::NoHit, &["ual_events"]),
        rule("R-PERSIST", "s-c", RuleOutcome::NoHit, &["signins"]),
        rule("R-SIGNIN", "s-c", RuleOutcome::NoEvidence, &["signins"]),
    ];
    let (got, _) = run(&stories, &rules);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].upn, "alice@contoso.example");
    assert_eq!(got[0].storylines, vec!["s-a"]);
    assert_eq!(got[0].stages, vec!["persistence"]);
}

/// A finding's actor is the user of the record it fires on: an admin's cmdlet on the actor's mailbox (the
/// storyline's actor is the affected user) expects no row for that user, and a hit on a record of another table than
/// the expectation names is not a hit on the actor's record.
#[test]
fn a_hit_on_somebody_elses_record_expects_no_row_for_the_actor() {
    let stories = [
        story(
            "s-adm",
            "positive",
            "alice@contoso.example",
            &[("admin_audit_events", "a1")],
        ),
        story(
            "s-tbl",
            "positive",
            "bob@contoso.example",
            &[("ual_events", "u7")],
        ),
        story(
            "s-unknown",
            "positive",
            "dave@contoso.example",
            &[("inbox_rules", "r1")],
        ),
    ];
    let rules = [
        rule(
            "R-PERSIST",
            "s-adm",
            RuleOutcome::Hit,
            &["admin_audit_events"],
        ),
        // The hit cites the signins table; bob's own record is in ual_events.
        rule("R-SIGNIN", "s-tbl", RuleOutcome::Hit, &["signins"]),
        // A state table no model reads an author from.
        rule("R-PERSIST", "s-unknown", RuleOutcome::Hit, &["inbox_rules"]),
    ];
    let (got, asked) = run(&stories, &rules);
    assert!(got.is_empty(), "{got:?}");
    assert!(asked.is_empty());
}

#[test]
fn stages_come_only_from_the_rules_that_hit_the_actors_own_records_in_the_stage_order() {
    let stories = [
        story(
            "s-a",
            "positive",
            "alice@contoso.example",
            &[("ual_events", "u1"), ("admin_audit_events", "a1")],
        ),
        story(
            "s-a2",
            "positive",
            "alice@contoso.example",
            &[("ual_events", "u2")],
        ),
    ];
    let rules = [
        rule("R-MAIL", "s-a2", RuleOutcome::Hit, &["ual_events"]),
        rule("R-PERSIST", "s-a", RuleOutcome::Hit, &["ual_events"]),
        rule("R-BOTH", "s-a", RuleOutcome::Hit, &["ual_events"]),
        rule("R-NONE", "s-a", RuleOutcome::Hit, &["ual_events"]),
        // Hits only the admin's record of s-a: adds no stage to alice.
        rule("R-SIGNIN", "s-a", RuleOutcome::Hit, &["admin_audit_events"]),
        // Rules that do not hit add nothing.
        rule("R-SIGNIN", "s-a2", RuleOutcome::NoHit, &["ual_events"]),
    ];
    let (got, _) = run(&stories, &rules);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].storylines, vec!["s-a", "s-a2"]);
    // suspicious_sign_in from R-BOTH only, persistence from two rules, mail_access from R-MAIL; R-SIGNIN's hit on the
    // admin's record is not alice's.
    assert_eq!(
        got[0].stages,
        vec!["suspicious_sign_in", "persistence", "mail_access"]
    );
}

#[test]
fn the_mailitemsaccessed_only_address_comes_from_the_expected_storylines_ual_records() {
    let stories = [
        story(
            "s-mia",
            "positive",
            "alice@contoso.example",
            &[("ual_events", "m1"), ("ual_events", "m2")],
        ),
        // Another storyline of bob: its keys must not be asked for alice.
        story(
            "s-bob",
            "positive",
            "bob@contoso.example",
            &[("ual_events", "m7")],
        ),
    ];
    let rules = [
        rule("R-MAIL", "s-mia", RuleOutcome::Hit, &["ual_events"]),
        rule("R-PERSIST", "s-bob", RuleOutcome::Hit, &["ual_events"]),
    ];
    let (got, asked) = run(&stories, &rules);
    let alice = got
        .iter()
        .find(|a| a.upn == "alice@contoso.example")
        .unwrap();
    assert_eq!(alice.addresses, vec!["198.51.100.9"]);
    let bob = got.iter().find(|a| a.upn == "bob@contoso.example").unwrap();
    assert!(bob.addresses.is_empty());
    // The facts are asked once per account, with that account's expected storylines' UAL keys only.
    assert_eq!(asked, vec![set(&["m1", "m2"]), set(&["m7"])]);
}

#[test]
fn a_storyline_without_an_expected_account_contributes_no_keys() {
    // s-mia delivers MailItemsAccessed records, but no rule hits them: no account, nothing asked.
    let stories = [story(
        "s-mia",
        "positive",
        "alice@contoso.example",
        &[("ual_events", "m1")],
    )];
    let rules = [rule(
        "R-MAIL",
        "s-mia",
        RuleOutcome::NoEvidence,
        &["ual_events"],
    )];
    let (got, asked) = run(&stories, &rules);
    assert!(got.is_empty());
    assert!(asked.is_empty());
}

#[test]
fn a_storyline_without_an_actor_expects_no_account() {
    let stories = [story("s-t", "positive", "", &[("ual_events", "u1")])];
    let rules = [rule("R-PERSIST", "s-t", RuleOutcome::Hit, &["ual_events"])];
    assert!(run(&stories, &rules).0.is_empty());
}

#[test]
fn accounts_are_sorted_by_upn() {
    let stories = [
        story(
            "s-z",
            "positive",
            "bob@contoso.example",
            &[("ual_events", "u7")],
        ),
        story(
            "s-a",
            "positive",
            "alice@contoso.example",
            &[("ual_events", "u1")],
        ),
    ];
    let rules = [
        rule("R-PERSIST", "s-z", RuleOutcome::Hit, &["ual_events"]),
        rule("R-PERSIST", "s-a", RuleOutcome::Hit, &["ual_events"]),
    ];
    let upns: Vec<_> = run(&stories, &rules).0.into_iter().map(|a| a.upn).collect();
    assert_eq!(upns, vec!["alice@contoso.example", "bob@contoso.example"]);
}
