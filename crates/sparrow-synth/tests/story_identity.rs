use sparrow_synth::coverage::{must_not_trigger, rules, triggers};
use sparrow_synth::scenario::{Polarity, StoryKind, load};
use sparrow_synth::story::{Evidence, apply};
use sparrow_synth::world::World;

fn world(name: &str) -> (World, Vec<sparrow_synth::story::StoryRecord>) {
    let mut w = World::build(&load(name).unwrap(), 42).unwrap();
    let recs = apply(&mut w).unwrap();
    (w, recs)
}

#[test]
fn coverage_matrix_is_complete_and_consistent() {
    let rs = rules();
    assert_eq!(rs.len(), 35);
    for r in rs {
        assert!(
            !r.positives.is_empty() && !r.lookalikes.is_empty(),
            "{}",
            r.id
        );
        assert!(
            !r.tables.is_empty() && !r.collectors.is_empty() && !r.logic.is_empty(),
            "{}",
            r.id
        );
        for k in &r.positives {
            assert!(triggers(*k).contains(&r.id.as_str()));
        }
    }
    // Every storyline kind is used by at least one rule.
    for k in StoryKind::ALL {
        assert!(
            !triggers(*k).is_empty() || !must_not_trigger(*k).is_empty(),
            "{k:?} unused"
        );
    }
    assert!(triggers(StoryKind::LowRiskConsent).contains(&"SPW-HAWK-006"));
    assert!(must_not_trigger(StoryKind::LowRiskConsent).contains(&"SPW-APP-001"));
}

#[test]
fn aitm_emits_one_consistent_story() {
    let (w, recs) = world("bec-aitm");
    let aitm = recs.iter().find(|r| r.id == "s-aitm").unwrap();
    assert_eq!(aitm.polarity, Polarity::Positive);
    let signin_ids: Vec<_> = aitm
        .evidence
        .iter()
        .filter_map(|e| match e {
            Evidence::SignIn(id) => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(signin_ids.len(), 3);
    let signins: Vec<_> = w
        .story
        .signins
        .iter()
        .filter(|s| signin_ids.contains(&s.id))
        .collect();
    let proxy = signins
        .iter()
        .find(|s| s.ip == w.attacker.proxy_ip)
        .unwrap();
    let replay = signins
        .iter()
        .find(|s| s.ip == w.attacker.replay_ip)
        .unwrap();
    assert_eq!(proxy.session_id, replay.session_id);
    assert_eq!(replay.user_agent, w.attacker.user_agent_axios);
    assert_eq!(proxy.risk_during, "high"); // bec-aitm is E5 (P2)
    assert!(aitm.evidence.iter().any(|e| matches!(e, Evidence::Risk(_))));
    assert!(
        aitm.evidence
            .iter()
            .any(|e| matches!(e, Evidence::RiskyUser(_)))
    );
}

#[test]
fn risk_levels_are_hidden_without_p2() {
    let (w, recs) = world("bec-e3-audit-gaps");
    let aitm = recs.iter().find(|r| r.id == "s-aitm").unwrap();
    for e in &aitm.evidence {
        if let Evidence::SignIn(id) = e {
            let s = w.story.signins.iter().find(|s| s.id == *id).unwrap();
            assert_eq!(s.risk_during, "hidden");
        }
    }
}

#[test]
fn consent_adds_grants_and_audit_events() {
    let (w, recs) = world("bec-aitm");
    let c = recs.iter().find(|r| r.id == "s-consent").unwrap();
    let app = w
        .apps
        .iter()
        .find(|a| a.display_name == "Mail Organizer Plus")
        .unwrap();
    let scopes: Vec<&str> = w
        .grants
        .iter()
        .filter(|g| g.client_app_id == app.app_id)
        .map(|g| g.scope.as_str())
        .collect();
    assert!(scopes.contains(&"Mail.ReadWrite") && scopes.contains(&"offline_access"));
    assert!(
        c.evidence
            .iter()
            .any(|e| matches!(e, Evidence::DirAudit(_)))
    );
    assert!(c.evidence.iter().any(|e| matches!(e, Evidence::Ual(_))));
}

#[test]
fn story_events_land_in_their_day() {
    let (w, recs) = world("bec-aitm");
    let aitm = recs.iter().find(|r| r.id == "s-aitm").unwrap();
    let d = w.day(aitm.time.date_naive());
    assert!(d.signins.iter().any(|s| s.ip == w.attacker.proxy_ip));
    let replay = w.attacker.replay_ip.to_string();
    assert!(d.ual.iter().any(|u| u.client_ip() == Some(replay.as_str())));
    assert!(
        d.ual
            .windows(2)
            .all(|p| (p[0].time, p[0].id) <= (p[1].time, p[1].id))
    );
}

#[test]
fn applying_is_deterministic() {
    let (a, ra) = world("hawk-investigate");
    let (b, rb) = world("hawk-investigate");
    assert_eq!(format!("{ra:?}"), format!("{rb:?}"));
    assert_eq!(format!("{:?}", a.story.ual), format!("{:?}", b.story.ual));
}

#[test]
fn story_values_are_reserved() {
    for name in sparrow_synth::scenario::builtin_names() {
        let (w, recs) = world(name);
        let text = format!(
            "{recs:?}{:?}{:?}{:?}{:?}{:?}{:?}",
            w.story, w.apps, w.grants, w.mfa, w.risky_users, w.mobile_devices
        );
        let bad = sparrow_synth::reserved::scan_text(&text);
        assert!(bad.is_empty(), "{name}: {bad:?}");
    }
}

#[test]
fn story_state_changes_match_their_events() {
    let (w, recs) = world("bec-aitm");
    let upn = &w.user(1).upn;
    // The admin's confirmation (after the AiTM detection) is the user's final risk state.
    let risky = &w.risky_users[upn];
    assert_eq!(
        (risky.state.as_str(), risky.level.as_str()),
        ("confirmedCompromised", "high")
    );
    assert_eq!(
        w.mfa[upn]
            .methods
            .iter()
            .filter(|m| *m == "microsoftAuthenticator")
            .count(),
        2
    );
    let helpdesk = w
        .apps
        .iter()
        .find(|a| a.display_name == "Helpdesk Portal")
        .unwrap();
    assert!(
        helpdesk
            .credentials
            .iter()
            .any(|c| c.on_service_principal && c.display_name == "sync")
    );
    let cert = recs.iter().find(|r| r.id == "l-cert").unwrap();
    assert_eq!(cert.actor, w.user(1).upn);
    let payroll = w
        .apps
        .iter()
        .find(|a| a.display_name.ends_with("Payroll Sync"))
        .unwrap();
    // The expiring certificate (within 30 days of the rotation) and its replacement.
    assert_eq!(payroll.credentials.len(), 2);
    assert!(payroll.credentials[0].end > cert.time);
    assert!(payroll.credentials[0].end <= cert.time + chrono::Duration::days(30));
    assert_eq!(payroll.credentials[1].start, cert.time);

    let (w, recs) = world("hawk-investigate");
    let mobile = recs.iter().find(|r| r.id == "s-mobile").unwrap();
    let dev = w
        .mobile_devices
        .iter()
        .find(|d| d.mailbox == w.user(2).upn && d.first_sync == mobile.time);
    assert!(dev.is_some());
    let old = w
        .mobile_devices
        .iter()
        .find(|d| d.mailbox == w.user(4).upn)
        .unwrap();
    assert!(old.first_sync < w.window_start() && old.last_sync >= w.window_start());
    let domain = recs.iter().find(|r| r.id == "s-domain").unwrap();
    let ops: Vec<&str> = w
        .story
        .ual
        .iter()
        .filter(|u| domain.evidence.contains(&Evidence::Ual(u.id)))
        .map(|u| u.operation.as_str())
        .collect();
    assert_eq!(
        ops,
        [
            "Add domain to company.",
            "Verify domain.",
            "Set domain authentication."
        ]
    );
}

#[test]
fn mailbox_login_is_recorded_but_not_logged() {
    let (w, recs) = world("bec-aitm");
    let aitm = recs.iter().find(|r| r.id == "s-aitm").unwrap();
    let login = w
        .story
        .ual
        .iter()
        .find(|u| u.operation == "MailboxLogin" && aitm.evidence.contains(&Evidence::Ual(u.id)))
        .unwrap();
    assert!(!w.logged(login), "MailboxLogin is in no default audit list");
    let logon = w
        .story
        .ual
        .iter()
        .find(|u| u.operation == "UserLoggedIn")
        .unwrap();
    assert!(w.logged(logon));
    assert!(
        !w.day(login.time.date_naive())
            .ual
            .iter()
            .any(|u| u.id == login.id)
    );
}

#[test]
fn plausible_travel_stays_below_airliner_speed() {
    let (w, recs) = world("bec-aitm");
    let travel = recs.iter().find(|r| r.id == "l-travel").unwrap();
    let s: Vec<_> = w
        .story
        .signins
        .iter()
        .filter(|s| travel.evidence.contains(&Evidence::SignIn(s.id)))
        .collect();
    assert_eq!(s.len(), 2);
    let (a, b) = (&s[0].location, &s[1].location);
    let (la1, lo1, la2, lo2) = (
        a.lat.to_radians(),
        a.lon.to_radians(),
        b.lat.to_radians(),
        b.lon.to_radians(),
    );
    let h = ((la2 - la1) / 2.0).sin().powi(2)
        + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
    let km = 2.0 * 6371.0 * h.sqrt().asin();
    let hours = (s[1].time - s[0].time).num_minutes() as f64 / 60.0;
    assert!(km >= 500.0 && km / hours < 900.0, "{km} km in {hours} h");
}

#[test]
fn directory_audits_and_risk_merge_baseline_and_story() {
    let (w, recs) = world("bec-aitm");
    let audits = w.directory_audits();
    for r in &recs {
        for e in &r.evidence {
            if let Evidence::DirAudit(id) = e {
                assert!(audits.iter().any(|a| &a.id == id), "{}", r.id);
            }
        }
    }
    assert!(
        audits
            .windows(2)
            .all(|p| (p[0].time, &p[0].id) <= (p[1].time, &p[1].id))
    );
    let risk = w.risk_detections();
    assert!(risk.iter().any(|r| r.event_type == "anomalousToken"));
    assert!(risk.len() > w.story.risk.len(), "baseline detection kept");
}

#[test]
fn no_ip_has_two_locations() {
    for name in [
        "bec-aitm",
        "hawk-investigate",
        "bec-e3-audit-gaps",
        "bec-o365-no-p1",
    ] {
        let (w, _) = world(name);
        let mut seen: std::collections::BTreeMap<std::net::IpAddr, (String, u32)> =
            std::collections::BTreeMap::new();
        for d in 0..w.scenario.window.days {
            let date = w.window_start().date_naive() + chrono::Duration::days(d.into());
            for s in w.day(date).signins {
                let loc = (s.location.city.clone(), s.asn);
                assert_eq!(s.asn, s.location.asn, "{name} {}", s.ip);
                let prev = seen.entry(s.ip).or_insert_with(|| loc.clone());
                assert_eq!(*prev, loc, "{name}: {} seen at two locations", s.ip);
            }
        }
    }
}

#[test]
fn risky_users_merge_baseline_and_story() {
    let (w, _) = world("bec-aitm");
    let all = w.risky_users();
    let u2 = &w.user(2).upn;
    assert_eq!(all.keys().filter(|k| *k == u2).count(), 1);
    assert_eq!(all[u2].state, "dismissed");
    assert_eq!(all[&w.user(1).upn].state, "confirmedCompromised");
}

#[test]
fn new_hire_registers_a_single_authenticator() {
    let (w, recs) = world("bec-aitm");
    let hire = recs.iter().find(|r| r.id == "l-newhire").unwrap();
    let m = &w.mfa[&hire.actor];
    assert_eq!(
        m.methods
            .iter()
            .filter(|x| *x == "microsoftAuthenticator")
            .count(),
        1
    );
    let update = w
        .story
        .ual
        .iter()
        .find(|u| u.operation == "Update user." && hire.evidence.contains(&Evidence::Ual(u.id)))
        .unwrap();
    let prop = &update.audit["ModifiedProperties"][0];
    assert_eq!(prop["Name"], "StrongAuthenticationPhoneAppDetail");
    assert_eq!(prop["OldValue"], "[]");
}

#[test]
fn consent_signin_uses_an_unknown_device() {
    let (w, recs) = world("bec-aitm");
    let c = recs.iter().find(|r| r.id == "s-consent").unwrap();
    let s = w
        .story
        .signins
        .iter()
        .find(|s| c.evidence.contains(&Evidence::SignIn(s.id)))
        .unwrap();
    assert_eq!(s.ip, w.attacker.replay_ip);
    assert!(s.device.device_id.is_nil() && s.device_managed.is_none());
}
