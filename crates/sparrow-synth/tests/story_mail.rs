use sparrow_synth::scenario::{StoryKind, load};
use sparrow_synth::story::{Evidence, StoryRecord, apply};
use sparrow_synth::world::World;

fn world(name: &str) -> (World, Vec<StoryRecord>) {
    let mut w = World::build(&load(name).unwrap(), 42).unwrap();
    let recs = apply(&mut w).unwrap();
    (w, recs)
}

fn ual_ids(r: &StoryRecord) -> Vec<uuid::Uuid> {
    r.evidence
        .iter()
        .filter_map(|e| match e {
            Evidence::Ual(id) => Some(*id),
            _ => None,
        })
        .collect()
}

#[test]
fn every_builtin_applies() {
    for name in sparrow_synth::scenario::builtin_names() {
        let (_, recs) = world(name);
        assert!(!recs.is_empty(), "{name}");
    }
}

#[test]
fn every_kind_is_exercised_by_a_builtin() {
    let mut seen = std::collections::BTreeSet::new();
    for name in sparrow_synth::scenario::builtin_names() {
        let (_, recs) = world(name);
        for r in recs {
            assert!(!r.evidence.is_empty(), "{name} {}", r.id);
            seen.insert(r.kind);
        }
    }
    for k in StoryKind::ALL {
        assert!(seen.contains(k), "{k:?} is in no built-in scenario");
    }
}

#[test]
fn finance_rule_state_and_event_agree() {
    let (w, recs) = world("bec-aitm");
    let r = recs.iter().find(|r| r.id == "s-rule").unwrap();
    let upn = &w.user(1).upn;
    let rule = w
        .inbox_rules
        .iter()
        .find(|x| &x.mailbox == upn && x.name == ".")
        .unwrap();
    assert_eq!(rule.move_to_folder.as_deref(), Some("RSS Feeds"));
    let ev = w
        .story
        .ual
        .iter()
        .find(|u| ual_ids(r).contains(&u.id))
        .unwrap();
    assert_eq!(ev.operation, "New-InboxRule");
    assert_eq!(
        ev.client_ip(),
        Some(w.attacker.replay_ip.to_string().as_str())
    );
}

#[test]
fn audit_tamper_stops_logging_from_its_time_on() {
    let (w, recs) = world("audit-tamper");
    let tamper = recs.iter().find(|r| r.id == "s-tamper").unwrap();
    assert!(!w.audit.ual_ingestion_enabled && w.audit.org_audit_disabled);
    // The tamper cmdlets themselves are logged; the later storylines are not.
    for id in ual_ids(tamper) {
        let u = w.story.ual.iter().find(|u| u.id == id).unwrap();
        assert!(w.logged(u), "{}", u.operation);
    }
    for later in ["s-mia", "s-fwd"] {
        let r = recs.iter().find(|r| r.id == later).unwrap();
        for id in ual_ids(r) {
            let u = w.story.ual.iter().find(|u| u.id == id).unwrap();
            assert!(!w.logged(u), "{later} {}", u.operation);
        }
    }
    let day = w.day(tamper.time.date_naive() + chrono::Duration::days(1));
    assert!(day.ual.is_empty(), "no UAL after ingestion was disabled");
}

#[test]
fn audit_tamper_keeps_earlier_mailbox_records() {
    let (w, recs) = world("audit-tamper");
    let tamper = recs.iter().find(|r| r.id == "s-tamper").unwrap();
    let upn = &w.user(1).upn;
    let mb = &w.mailboxes[upn];
    assert!(!mb.audit_enabled && mb.bypass);
    // The victim's own baseline mailbox records before the tamper are still logged.
    let day = w.day(tamper.time.date_naive() - chrono::Duration::days(1));
    assert!(day.ual.iter().any(|u| &u.user_id == upn
        && u.audit.get("MailboxOwnerUPN").and_then(|v| v.as_str()) == Some(upn.as_str())));
}

#[test]
fn customized_audit_suppresses_mia_and_send() {
    let (w, recs) = world("bec-e3-audit-gaps");
    for id in ["s-mia", "s-send", "s-search"] {
        let r = recs.iter().find(|r| r.id == id).unwrap();
        let ids = ual_ids(r);
        assert!(!ids.is_empty());
        assert!(
            ids.iter()
                .all(|i| !w.logged(w.story.ual.iter().find(|u| u.id == *i).unwrap())),
            "{id}"
        );
    }
}

#[test]
fn mia_burst_reads_messages_that_exist_in_the_trace() {
    let (w, recs) = world("bec-aitm");
    let r = recs.iter().find(|r| r.id == "s-mia").unwrap();
    let mut day_ids = std::collections::BTreeSet::new();
    for d in 0..w.scenario.window.days {
        let date = w.window_start().date_naive() + chrono::Duration::days(d.into());
        for t in w.day(date).trace {
            day_ids.insert(t.internet_message_id);
        }
    }
    let ids = ual_ids(r);
    assert_eq!(ids.len(), 12);
    for u in w.story.ual.iter().filter(|u| ids.contains(&u.id)) {
        for f in u.audit["Folders"].as_array().unwrap() {
            for i in f["FolderItems"].as_array().unwrap() {
                assert!(day_ids.contains(i["InternetMessageId"].as_str().unwrap()));
            }
        }
    }
}

#[test]
fn hawk_bug_lookalike_is_recorded() {
    let (w, recs) = world("hawk-investigate");
    let r = recs.iter().find(|r| r.id == "l-admok").unwrap();
    let u = w
        .story
        .ual
        .iter()
        .find(|u| ual_ids(r).contains(&u.id))
        .unwrap();
    let params = u.audit["Parameters"].as_array().unwrap();
    assert!(
        params
            .iter()
            .any(|p| p["Name"] == "DeleteMessage" && p["Value"] == "False")
    );
}

#[test]
fn forwarding_removed_ends_without_forwarding() {
    let (w, recs) = world("hawk-investigate");
    let r = recs.iter().find(|r| r.id == "l-fwdoff").unwrap();
    assert_eq!(ual_ids(r).len(), 2);
    assert!(w.mailboxes[&w.user(3).upn].forwarding_smtp.is_none());
    assert!(w.mailboxes[&w.user(6).upn].forwarding_smtp.is_some());
}

#[test]
fn storyline_values_are_reserved() {
    use sparrow_synth::reserved::scan_text;
    for name in sparrow_synth::scenario::builtin_names() {
        let (w, _) = world(name);
        let mut texts: Vec<String> = w.story.ual.iter().map(|u| u.audit_data_text()).collect();
        for e in &w.emails {
            texts.push(format!(
                "{} {} {} {} {} {}",
                e.message_id,
                e.from,
                e.return_path,
                e.received.join(" "),
                e.auth_results,
                e.body
            ));
        }
        for t in &w.story.trace {
            texts.push(format!("{t:?}"));
        }
        for text in texts {
            let bad = scan_text(&text);
            assert!(bad.is_empty(), "{name}: {bad:?} in {text}");
        }
    }
}
