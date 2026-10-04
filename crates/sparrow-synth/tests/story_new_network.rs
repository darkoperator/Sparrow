//! The SPW-ID-007 storylines (bec-aitm): a stolen session replayed from a residential ISP of the
//! victim's own country followed by an inbox rule within the hour, and the look-alikes that carry
//! one half or both halves too far apart (a phone on a new carrier, a rule edit two hours after a
//! new network, the admin's routine role changes from the office).

use chrono::Duration;
use sparrow_synth::events::{SignIn, Ual};
use sparrow_synth::scenario::load;
use sparrow_synth::story::{Evidence, StoryRecord, apply};
use sparrow_synth::world::{HOSTING_ASNS, MICROSOFT_ASN, World};
use sparrow_synth::writers::window_days;
use std::collections::BTreeSet;

/// The persistence operations SPW-ID-007 triggers on (UAL spelling, lower case, no final ".").
const PERSISTENCE: [&str; 10] = [
    "new-inboxrule",
    "set-inboxrule",
    "updateinboxrules",
    "add-mailboxpermission",
    "consent to application",
    "add app role assignment grant to user",
    "add app role assignment to service principal",
    "user registered security info",
    "add member to role",
    "set-mailbox",
];

fn world() -> (World, Vec<StoryRecord>) {
    let mut w = World::build(&load("bec-aitm").unwrap(), 42).unwrap();
    let recs = apply(&mut w).unwrap();
    (w, recs)
}

fn record<'a>(recs: &'a [StoryRecord], id: &str, kind: &str) -> &'a StoryRecord {
    let r = recs
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("bec-aitm has no storyline {id}"));
    assert_eq!(r.kind.as_str(), kind, "{id}");
    r
}

/// The storyline's own sign-ins.
fn own_signins<'a>(w: &'a World, r: &StoryRecord) -> Vec<&'a SignIn> {
    let ids: BTreeSet<_> = r
        .evidence
        .iter()
        .filter_map(|e| match e {
            Evidence::SignIn(i) => Some(*i),
            _ => None,
        })
        .collect();
    let v: Vec<&SignIn> = w
        .story
        .signins
        .iter()
        .filter(|s| ids.contains(&s.id))
        .collect();
    assert!(!v.is_empty(), "{} has no sign-ins", r.id);
    v
}

fn own_ual<'a>(w: &'a World, r: &StoryRecord) -> Vec<&'a Ual> {
    let ids: BTreeSet<_> = r
        .evidence
        .iter()
        .filter_map(|e| match e {
            Evidence::Ual(i) => Some(*i),
            _ => None,
        })
        .collect();
    w.story.ual.iter().filter(|u| ids.contains(&u.id)).collect()
}

/// Every successful sign-in of `upn` in the window (baseline and storylines).
fn history(w: &World, upn: &str) -> Vec<SignIn> {
    window_days(w)
        .into_iter()
        .flat_map(|d| d.signins)
        .filter(|s| s.user == upn && s.error_code == 0)
        .collect()
}

fn is_persistence(op: &str) -> bool {
    PERSISTENCE.contains(&op.trim_end_matches('.').to_lowercase().as_str())
}

/// The first sign-in of `s.user` from `s`'s ASN is `s` itself, on a day after at least three
/// earlier active days, from a country the user signed in from on an earlier day, from an ordinary
/// (not hosting, not Microsoft) network.
fn assert_first_from_a_new_network(w: &World, s: &SignIn) {
    let all = history(w, &s.user);
    let day = s.time.date_naive();
    let earlier_days: BTreeSet<_> = all
        .iter()
        .map(|x| x.time.date_naive())
        .filter(|d| *d < day)
        .collect();
    assert!(earlier_days.len() >= 3, "{}: {earlier_days:?}", s.user);
    assert!(
        !all.iter()
            .any(|x| x.location.asn == s.location.asn && x.time < s.time),
        "{}: AS{} was used before {}",
        s.user,
        s.location.asn,
        s.time
    );
    assert!(
        all.iter()
            .any(|x| x.location.country_iso == s.location.country_iso && x.time.date_naive() < day),
        "{}: {} is a new country",
        s.user,
        s.location.country_iso
    );
    assert!(!HOSTING_ASNS.iter().any(|(a, _)| *a == s.location.asn));
    assert_ne!(s.location.asn, MICROSOFT_ASN.0);
    assert!(!["medium", "high"].contains(&s.risk_during.as_str()));
}

/// The user's persistence records (UAL, every source) between `from` and `to`.
fn persistence_between(
    w: &World,
    upn: &str,
    from: chrono::DateTime<chrono::Utc>,
    to: chrono::DateTime<chrono::Utc>,
) -> Vec<Ual> {
    window_days(w)
        .into_iter()
        .flat_map(|d| d.ual)
        .filter(|u| {
            u.user_id.eq_ignore_ascii_case(upn)
                && u.time >= from
                && u.time <= to
                && is_persistence(&u.operation)
        })
        .collect()
}

#[test]
fn the_replay_signs_in_from_a_new_same_country_isp_then_hides_finance_mail_within_the_hour() {
    let (w, recs) = world();
    let r = record(&recs, "s-replay-rule", "residential_replay_rule");
    let user = w.user_by_upn(&r.actor).unwrap().clone();
    let signins = own_signins(&w, r);
    // The victim's own MFA sign-in from home creates the session; the replay uses it.
    let home = signins
        .iter()
        .find(|s| s.ip == user.home_ip)
        .expect("the victim's own sign-in");
    let replay = signins
        .iter()
        .find(|s| s.ip != user.home_ip)
        .expect("the replayed sign-in");
    assert_eq!(replay.session_id, home.session_id);
    assert!(replay.time > home.time && replay.time - home.time <= Duration::minutes(60));
    assert_ne!(replay.location.asn, user.home.asn);
    assert_eq!(replay.location.country_iso, user.home.country_iso);
    assert_eq!(
        replay.user_agent, user.client.user_agent,
        "no scripted agent"
    );
    assert_eq!(replay.error_code, 0);
    assert_first_from_a_new_network(&w, replay);
    // The finance rule from the replay address, in the replayed session, within the hour.
    let rules: Vec<&Ual> = own_ual(&w, r)
        .into_iter()
        .filter(|u| u.operation == "New-InboxRule")
        .collect();
    assert_eq!(rules.len(), 1);
    let rule = rules[0];
    assert_eq!(rule.client_ip(), Some(replay.ip.to_string().as_str()));
    assert!(rule.time > replay.time && rule.time - replay.time <= Duration::minutes(60));
    assert!(
        r.evidence
            .iter()
            .any(|e| matches!(e, Evidence::InboxRule { mailbox, .. } if *mailbox == user.upn))
    );
}

#[test]
fn a_phone_on_a_new_carrier_changes_nothing() {
    let (w, recs) = world();
    let r = record(&recs, "l-carrier", "new_carrier_phone");
    let user = w.user_by_upn(&r.actor).unwrap().clone();
    let signins = own_signins(&w, r);
    assert!(signins.len() >= 2, "the phone keeps using the carrier");
    let first = signins.iter().min_by_key(|s| s.time).unwrap();
    assert_ne!(first.location.asn, user.home.asn);
    assert_first_from_a_new_network(&w, first);
    // No persistence in the day that follows.
    let after = persistence_between(&w, &user.upn, first.time, first.time + Duration::hours(24));
    assert!(after.is_empty(), "{after:?}");
}

#[test]
fn the_users_own_rule_edit_comes_two_hours_after_the_new_network() {
    let (w, recs) = world();
    let r = record(&recs, "l-rule-2h", "rule_edit_after_new_network");
    let user = w.user_by_upn(&r.actor).unwrap().clone();
    let first = *own_signins(&w, r).iter().min_by_key(|s| s.time).unwrap();
    assert_first_from_a_new_network(&w, first);
    let edits: Vec<&Ual> = own_ual(&w, r)
        .into_iter()
        .filter(|u| u.operation == "UpdateInboxRules")
        .collect();
    assert_eq!(edits.len(), 1);
    let gap = edits[0].time - first.time;
    assert!(
        gap > Duration::minutes(90) && gap <= Duration::minutes(150),
        "{gap}"
    );
    // From the office, not from the new network.
    assert_eq!(
        edits[0].client_ip(),
        Some(user.office_ip.to_string().as_str())
    );
    let within = persistence_between(&w, &user.upn, first.time, first.time + Duration::hours(1));
    assert!(within.is_empty(), "{within:?}");
}

#[test]
fn the_admins_role_changes_follow_a_sign_in_from_the_office() {
    let (w, recs) = world();
    let r = record(&recs, "l-roles", "admin_role_changes");
    let admin = w.admins[0].clone();
    let signin = own_signins(&w, r)
        .into_iter()
        .find(|s| s.user == admin.upn)
        .expect("the admin's sign-in");
    assert_eq!(signin.ip, admin.office_ip);
    // The office is a network the admin used on earlier days.
    assert!(
        history(&w, &admin.upn)
            .iter()
            .any(|x| x.location.asn == signin.location.asn
                && x.time.date_naive() < signin.time.date_naive())
    );
    let audits: Vec<_> = w
        .story
        .audits
        .iter()
        .filter(|a| {
            r.evidence
                .iter()
                .any(|e| matches!(e, Evidence::DirAudit(id) if *id == a.id))
        })
        .collect();
    assert_eq!(audits.len(), 2);
    for a in &audits {
        assert_eq!(a.activity, "Add member to role");
        assert_eq!(a.category, "RoleManagement");
        assert_eq!(a.initiated_by.upn.as_deref(), Some(admin.upn.as_str()));
        assert_eq!(a.initiated_by.ip, Some(admin.office_ip));
        assert!(a.time > signin.time && a.time - signin.time <= Duration::minutes(60));
    }
    let ual = own_ual(&w, r);
    assert_eq!(
        ual.iter()
            .filter(|u| u.operation == "Add member to role.")
            .count(),
        2
    );
    // The tenant's role list holds the two new assignments of the member.
    let member = w.user_by_upn(&r.actor).unwrap();
    let roles: BTreeSet<_> = w
        .roles
        .iter()
        .filter(|x| x.principal == member.upn)
        .map(|x| x.role.as_str())
        .collect();
    assert!(
        roles.contains("Helpdesk Administrator") && roles.contains("Reports Reader"),
        "{roles:?}"
    );
}
