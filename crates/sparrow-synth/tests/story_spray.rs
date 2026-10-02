//! The r6 spray and cloud-service storylines, in the shape the collectors export: the connector's
//! backend sign-ins are interactive rows, a taken-over spray source has more failed-only users than
//! takeovers, stale accounts fail behind an office egress that more users succeed from, and the
//! other-ASN positive uses the connector's application from another hosting ASN.

use sparrow_synth::events::{SignIn, SignInType};
use sparrow_synth::scenario::load;
use sparrow_synth::story::{Evidence, StoryRecord, apply};
use sparrow_synth::world::World;
use std::collections::BTreeSet;

fn world() -> (World, Vec<StoryRecord>) {
    let mut w = World::build(&load("password-spray").unwrap(), 42).unwrap();
    let recs = apply(&mut w).unwrap();
    (w, recs)
}

fn signins_of<'a>(w: &'a World, recs: &[StoryRecord], id: &str) -> Vec<&'a SignIn> {
    let rec = recs.iter().find(|r| r.id == id).unwrap();
    let ids: BTreeSet<_> = rec
        .evidence
        .iter()
        .filter_map(|e| match e {
            Evidence::SignIn(i) => Some(*i),
            _ => None,
        })
        .collect();
    let out: Vec<&SignIn> = w
        .story
        .signins
        .iter()
        .filter(|s| ids.contains(&s.id))
        .collect();
    assert!(!out.is_empty(), "{id} has no sign-ins");
    out
}

const CREDENTIAL: [i64; 7] = [50126, 50053, 50034, 50056, 50064, 50055, 50057];

#[test]
fn the_connectors_backend_is_recorded_as_interactive_rows() {
    let (w, recs) = world();
    let onboarding = signins_of(&w, &recs, "s-onboard");
    assert!(onboarding.len() >= 18);
    for s in onboarding
        .iter()
        .chain(signins_of(&w, &recs, "l-connector").iter())
    {
        assert_eq!(s.event_type, SignInType::Interactive);
        assert_eq!(s.client_app, "Mobile Apps and Desktop clients");
        assert_eq!(s.error_code, 0);
    }
    let users: BTreeSet<_> = onboarding.iter().map(|s| s.user.clone()).collect();
    assert!(users.len() >= 6);
}

#[test]
fn a_taken_over_proxy_sprays_more_failed_only_users_than_it_takes() {
    let (w, recs) = world();
    let all = signins_of(&w, &recs, "s-takeover");
    let failed: BTreeSet<_> = all
        .iter()
        .filter(|s| CREDENTIAL.contains(&s.error_code))
        .map(|s| s.user.clone())
        .collect();
    let taken: BTreeSet<_> = all
        .iter()
        .filter(|s| s.error_code == 0)
        .map(|s| s.user.clone())
        .collect();
    assert_eq!(taken.len(), 5);
    assert!(failed.len() >= 15, "{}", failed.len());
    assert!(taken.is_subset(&failed));
    assert!(failed.len() - taken.len() > taken.len());
    let ips: BTreeSet<_> = all.iter().map(|s| s.ip).collect();
    assert_eq!(ips.len(), 1);
}

#[test]
fn stale_accounts_fail_behind_an_office_that_more_users_sign_in_from() {
    let (w, recs) = world();
    let all = signins_of(&w, &recs, "l-stale");
    let failed: BTreeSet<_> = all
        .iter()
        .filter(|s| s.error_code != 0)
        .map(|s| s.user.clone())
        .collect();
    let ok: BTreeSet<_> = all
        .iter()
        .filter(|s| s.error_code == 0)
        .map(|s| s.user.clone())
        .collect();
    assert_eq!(failed.len(), 5);
    assert!(failed.is_disjoint(&ok), "stale accounts never succeed");
    assert!(ok.len() > failed.len());
    for s in all.iter().filter(|s| s.error_code != 0) {
        assert!([50057, 50034, 50055].contains(&s.error_code));
        assert!(s.session_id.is_nil());
    }
    assert_eq!(all.iter().map(|s| s.ip).collect::<BTreeSet<_>>().len(), 1);
}

#[test]
fn the_other_asn_positive_uses_the_connectors_app_from_a_different_hosting_asn() {
    let (w, recs) = world();
    let connector = signins_of(&w, &recs, "s-onboard");
    let (app, asn) = (connector[0].app_id, connector[0].asn);
    let other = signins_of(&w, &recs, "s-otherasn");
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].app_id, app);
    assert_ne!(other[0].asn, asn);
    // The VPS storyline is on a different hosting ASN than the connector too.
    for s in signins_of(&w, &recs, "s-vps")
        .iter()
        .filter(|s| s.error_code == 0)
    {
        assert_ne!(s.asn, asn);
    }
}

#[test]
fn a_longstanding_connector_signs_in_from_day_one_from_a_far_region_of_the_users_country() {
    let (w, recs) = world();
    let all = signins_of(&w, &recs, "l-longstanding");
    let users: BTreeSet<_> = all.iter().map(|s| s.user.clone()).collect();
    assert!(users.len() >= 6);
    let days: BTreeSet<_> = all.iter().map(|s| s.time.date_naive()).collect();
    assert!(days.len() >= 14);
    let first = recs
        .iter()
        .find(|r| r.id == "l-longstanding")
        .unwrap()
        .time
        .date_naive();
    assert_eq!(days.iter().next().copied(), Some(first));
    for s in &all {
        assert_eq!(s.event_type, SignInType::Interactive);
        let home = &w.users.iter().find(|u| u.upn == s.user).unwrap().home;
        assert_eq!(s.location.country_iso, home.country_iso);
        // About 670 km north of the user (6 degrees of latitude), on a hosting ASN of its own.
        assert!((s.location.lat - home.lat - 6.0).abs() < 1e-9);
        assert_ne!(s.asn, home.asn);
    }
    // A different application than the onboarded connector.
    let onboarded = signins_of(&w, &recs, "s-onboard");
    assert_ne!(all[0].app_id, onboarded[0].app_id);
}

#[test]
fn window_mistypes_include_day_one_and_every_mistyper_succeeds() {
    let (w, recs) = world();
    let all = signins_of(&w, &recs, "l-window");
    let start = recs
        .iter()
        .find(|r| r.id == "l-window")
        .unwrap()
        .time
        .date_naive();
    let failed: BTreeSet<_> = all
        .iter()
        .filter(|s| s.error_code != 0)
        .map(|s| s.user.clone())
        .collect();
    let ok: BTreeSet<_> = all
        .iter()
        .filter(|s| s.error_code == 0)
        .map(|s| s.user.clone())
        .collect();
    assert!(failed.len() >= 5 && failed.len() <= 8, "{}", failed.len());
    assert!(failed.is_subset(&ok));
    assert!(ok.len() >= 8);
    let fail_days: BTreeSet<_> = all
        .iter()
        .filter(|s| s.error_code != 0)
        .map(|s| s.time.date_naive())
        .collect();
    assert!(fail_days.contains(&start), "mistypes on the first day");
    assert!(fail_days.len() >= 5, "spread over the window");
}

#[test]
fn the_conference_network_is_not_a_mobile_carrier() {
    let (w, recs) = world();
    let all = signins_of(&w, &recs, "l-conf");
    assert!(all.len() >= 3);
    // One venue address on the organiser's own (residential) ISP network, the same for every attendee.
    let organiser = &w.users.iter().find(|u| u.upn == all[0].user).unwrap().home;
    let ips: BTreeSet<_> = all.iter().map(|s| s.ip).collect();
    assert_eq!(ips.len(), 1);
    for s in all {
        assert_eq!(s.asn, organiser.asn);
        assert!(!s.location.asn_org.to_lowercase().contains("mobile"));
    }
}
