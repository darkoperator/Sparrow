use chrono::{TimeZone, Utc};
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::notes::{self, NoteTarget};
use sparrow_core::case::timeline_entries::{self as te, EntryEdit, EvidenceRef, NewEntry, Phase};
use sparrow_core::case::{audit, review};
use sparrow_core::{Case, Error};

/// A case with provenance for three evidence records: signins:k1, signins:k2 and ual_events:abc:def (a key with a
/// colon), each sighted in one source file.
fn case_with_evidence() -> Case {
    let c = Case::in_memory().unwrap();
    c.conn()
        .execute_batch(
            "INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('invictus', '/e/T1', 't', 't1');
             INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status)
                 VALUES (1, 'SignInLogs/signins.json', 100, 'aa', 'parsed');
             INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end,
                                         byte_offset, byte_length, raw_sha256) VALUES
                 ('signins', 'k1', 1, 0, 1, 1, 0, 50, 'r1'),
                 ('signins', 'k2', 1, 1, 2, 2, 50, 50, 'r2'),
                 ('ual_events', 'abc:def', 1, 2, 3, 3, 100, 10, 'r3');",
        )
        .unwrap();
    c
}

fn agent() -> Actor {
    Actor::agent("claude", Some("carlos")).unwrap()
}

fn carlos() -> Reviewer {
    Reviewer::analyst("carlos").unwrap()
}

fn ev() -> Vec<EvidenceRef> {
    vec![EvidenceRef::parse("signins:k1").unwrap()]
}

fn new_entry(evidence: Vec<EvidenceRef>) -> NewEntry {
    NewEntry {
        tenant_key: Some("t1".into()),
        event_time: Utc.with_ymd_and_hms(2026, 8, 3, 9, 0, 0).unwrap(),
        title: "AiTM sign-in".into(),
        narrative: Some("replayed session".into()),
        phase: Phase::InitialAccess,
        evidence,
    }
}

fn one(c: &Case, id: &str) -> te::Entry {
    te::list(c.conn(), None, None)
        .unwrap()
        .into_iter()
        .find(|e| e.entry_id == id)
        .unwrap_or_else(|| panic!("no entry {id}"))
}

fn is_decision(e: &Error) -> bool {
    matches!(e, Error::Decision(_))
}

fn audit_len(c: &Case) -> usize {
    audit::log(c.conn(), None).unwrap().len()
}

#[test]
fn propose_then_verify() {
    let c = case_with_evidence();
    let (id, p) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    assert_eq!(id.len(), 12);
    assert_eq!(
        (
            p.action.as_str(),
            p.object_type.as_str(),
            p.object_id.as_str()
        ),
        ("propose_entry", "timeline_entry", id.as_str())
    );
    assert_eq!(p.before, None);
    assert_eq!(p.after.as_ref().unwrap()["status"], "proposed");
    let e = one(&c, &id);
    assert_eq!(e.status, "proposed");
    assert_eq!(e.decided_at, p.ts);
    assert_eq!(e.created_at, p.ts);
    let v = te::verify(c.conn(), &agent(), &id).unwrap();
    assert_eq!(v.action, "verify_entry");
    assert_eq!(v.before.as_ref().unwrap()["status"], "proposed");
    let e = &te::list(c.conn(), Some("verified"), None).unwrap()[0];
    assert_eq!(e.entry_id, id);
    assert_eq!(e.decided_by, "agent:claude");
    assert_eq!(e.on_behalf_of.as_deref(), Some("analyst:carlos"));
    assert_eq!(e.review_state, "pending_review");
    assert_eq!(e.decided_at, v.ts);
    assert_eq!(e.phase, "initial_access");
    assert_eq!(e.tenant_key.as_deref(), Some("t1"));
    assert_eq!(e.narrative.as_deref(), Some("replayed session"));
    assert_eq!(e.evidence, ev());
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn verify_needs_existing_evidence() {
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(vec![])).unwrap();
    let err = te::verify(c.conn(), &agent(), &id).unwrap_err();
    assert!(is_decision(&err), "{err:?}");
    assert_eq!(one(&c, &id).status, "proposed");
    let err = te::propose(
        c.conn(),
        &agent(),
        new_entry(vec![EvidenceRef::parse("signins:missing").unwrap()]),
    )
    .unwrap_err();
    assert!(is_decision(&err), "{err:?}");
    // The table matters too: k1 exists in signins, not in ual_events.
    assert!(
        te::propose(
            c.conn(),
            &agent(),
            new_entry(vec![EvidenceRef::parse("ual_events:k1").unwrap()])
        )
        .is_err()
    );
    assert_eq!(te::list(c.conn(), None, None).unwrap().len(), 1);
    assert_eq!(audit_len(&c), 1);
}

#[test]
fn propose_validates_its_input() {
    let c = case_with_evidence();
    let mut blank = new_entry(ev());
    blank.title = "  ".into();
    assert!(is_decision(
        &te::propose(c.conn(), &agent(), blank).unwrap_err()
    ));
    assert!(is_decision(&Phase::parse("lateral").unwrap_err()));
    for p in Phase::ALL {
        assert_eq!(Phase::parse(p.as_str()).unwrap(), p);
    }
    assert!(te::list(c.conn(), Some("done"), None).is_err());
    assert!(te::list(c.conn(), None, Some("ok")).is_err());
    assert_eq!(audit_len(&c), 0);
}

#[test]
fn editing_a_proposed_entry_updates_it_in_place() {
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let edit = EntryEdit {
        title: Some("AiTM sign-in from VPS".into()),
        phase: Some(Phase::Persistence),
        evidence: Some(vec![
            EvidenceRef::parse("signins:k2").unwrap(),
            EvidenceRef::parse("ual_events:abc:def").unwrap(),
        ]),
        ..Default::default()
    };
    let (same, e) = te::edit(c.conn(), &agent(), &id, edit).unwrap();
    assert_eq!(same, id);
    assert_eq!(e.action, "edit_entry");
    let got = one(&c, &id);
    assert_eq!(
        (got.title.as_str(), got.phase.as_str()),
        ("AiTM sign-in from VPS", "persistence")
    );
    assert_eq!(
        got.narrative.as_deref(),
        Some("replayed session"),
        "untouched fields stay"
    );
    assert_eq!(got.evidence.len(), 2);
    assert_eq!(te::list(c.conn(), None, None).unwrap().len(), 1);
    // An edit that changes nothing, or names missing evidence, is refused.
    assert!(is_decision(
        &te::edit(c.conn(), &agent(), &id, EntryEdit::default()).unwrap_err()
    ));
    let bad = EntryEdit {
        evidence: Some(vec![EvidenceRef::parse("signins:nope").unwrap()]),
        ..Default::default()
    };
    assert!(te::edit(c.conn(), &agent(), &id, bad).is_err());
    assert_eq!(one(&c, &id).evidence.len(), 2);
}

#[test]
fn editing_a_verified_entry_supersedes_it_only_when_the_new_one_is_verified() {
    let c = case_with_evidence();
    let (old, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    te::verify(c.conn(), &agent(), &old).unwrap();
    let (new, p) = te::edit(
        c.conn(),
        &agent(),
        &old,
        EntryEdit {
            title: Some("AiTM sign-in from VPS".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_ne!(new, old);
    assert_eq!(
        (p.action.as_str(), p.object_id.as_str()),
        ("propose_entry", new.as_str())
    );
    let n = one(&c, &new);
    assert_eq!(n.supersedes.as_deref(), Some(old.as_str()));
    assert_eq!(n.status, "proposed");
    assert_eq!(n.evidence, ev(), "the evidence is carried over");
    assert_eq!(n.narrative.as_deref(), Some("replayed session"));
    assert_eq!(
        te::list(c.conn(), Some("verified"), None).unwrap().len(),
        1,
        "old stays verified"
    );
    te::verify(c.conn(), &agent(), &new).unwrap();
    let sup = te::list(c.conn(), Some("superseded"), None).unwrap();
    assert_eq!(sup.len(), 1);
    assert_eq!(sup[0].entry_id, old);
    let verified = te::list(c.conn(), Some("verified"), None).unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].entry_id, new);
    // A superseded entry is final: no edit, verify or reject.
    assert!(
        te::edit(
            c.conn(),
            &agent(),
            &old,
            EntryEdit {
                title: Some("x".into()),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(te::verify(c.conn(), &agent(), &old).is_err());
    assert!(te::reject(c.conn(), &agent(), &old, "dup").is_err());
}

#[test]
fn a_second_successor_cannot_supersede_twice() {
    let c = case_with_evidence();
    let (old, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    te::verify(c.conn(), &agent(), &old).unwrap();
    let edit = |t: &str| EntryEdit {
        title: Some(t.into()),
        ..Default::default()
    };
    let (a, _) = te::edit(c.conn(), &agent(), &old, edit("a")).unwrap();
    let (b, _) = te::edit(c.conn(), &agent(), &old, edit("b")).unwrap();
    te::verify(c.conn(), &agent(), &a).unwrap();
    let err = te::verify(c.conn(), &agent(), &b).unwrap_err();
    assert!(is_decision(&err), "{err:?}");
    assert_eq!(te::list(c.conn(), Some("verified"), None).unwrap().len(), 1);
}

#[test]
fn rejected_entries_cannot_be_edited() {
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    assert!(is_decision(
        &te::reject(c.conn(), &agent(), &id, "  ").unwrap_err()
    ));
    let r = te::reject(c.conn(), &agent(), &id, "duplicate").unwrap();
    assert_eq!(
        (r.action.as_str(), r.reason.as_deref()),
        ("reject_entry", Some("duplicate"))
    );
    assert_eq!(one(&c, &id).status, "rejected");
    let err = te::edit(
        c.conn(),
        &agent(),
        &id,
        EntryEdit {
            title: Some("x".into()),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(is_decision(&err), "{err:?}");
    assert!(te::verify(c.conn(), &agent(), &id).is_err());
    assert!(te::reject(c.conn(), &agent(), &id, "again").is_err());
    assert!(te::verify(c.conn(), &agent(), "nope").is_err());
}

#[test]
fn discarding_a_verify_returns_the_entry_to_proposed() {
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let v = te::verify(c.conn(), &agent(), &id).unwrap();
    review::review_discard(c.conn(), &carlos(), "timeline_entry", &id, v.seq, None).unwrap();
    let e = &te::list(c.conn(), Some("proposed"), None).unwrap()[0];
    assert_eq!(e.entry_id, id);
    assert_eq!(e.review_state, "discarded");
    assert_eq!(e.reviewed_by.as_deref(), Some("analyst:carlos"));
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn discarding_a_verify_that_superseded_restores_the_old_entry() {
    let c = case_with_evidence();
    let (old, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    te::verify(c.conn(), &agent(), &old).unwrap();
    let (new, _) = te::edit(
        c.conn(),
        &agent(),
        &old,
        EntryEdit {
            narrative: Some("from a VPS".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let v = te::verify(c.conn(), &agent(), &new).unwrap();
    assert_eq!(one(&c, &old).status, "superseded");
    // The superseded entry is reviewed through its successor only.
    let old_seq = review::latest_decision_seq(c.conn(), "timeline_entry", &old)
        .unwrap()
        .unwrap();
    assert!(
        review::review_discard(c.conn(), &carlos(), "timeline_entry", &old, old_seq, None).is_err()
    );
    review::review_discard(
        c.conn(),
        &carlos(),
        "timeline_entry",
        &new,
        v.seq,
        Some("keep the first"),
    )
    .unwrap();
    assert_eq!(one(&c, &old).status, "verified");
    assert_eq!(one(&c, &new).status, "proposed");
    assert_eq!(te::list(c.conn(), Some("verified"), None).unwrap().len(), 1);
}

#[test]
fn discarding_a_propose_rejects_the_entry() {
    let c = case_with_evidence();
    let (id, p) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    review::review_discard(
        c.conn(),
        &carlos(),
        "timeline_entry",
        &id,
        p.seq,
        Some("not relevant"),
    )
    .unwrap();
    let e = one(&c, &id);
    assert_eq!(
        (e.status.as_str(), e.review_state.as_str()),
        ("rejected", "discarded")
    );
    assert_eq!(e.review_comment.as_deref(), Some("not relevant"));
}

#[test]
fn discarding_an_edit_restores_fields_and_evidence() {
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let edit = EntryEdit {
        title: Some("changed".into()),
        event_time: Some(Utc.with_ymd_and_hms(2026, 8, 4, 10, 30, 0).unwrap()),
        narrative: Some("other".into()),
        evidence: Some(vec![
            EvidenceRef::parse("signins:k2").unwrap(),
            EvidenceRef::parse("signins:k1").unwrap(),
        ]),
        ..Default::default()
    };
    let (_, e) = te::edit(c.conn(), &agent(), &id, edit).unwrap();
    review::review_discard(c.conn(), &carlos(), "timeline_entry", &id, e.seq, None).unwrap();
    let got = one(&c, &id);
    assert_eq!(got.title, "AiTM sign-in");
    assert_eq!(
        got.event_time,
        Utc.with_ymd_and_hms(2026, 8, 3, 9, 0, 0).unwrap()
    );
    assert_eq!(got.narrative.as_deref(), Some("replayed session"));
    assert_eq!(got.evidence, ev());
    assert_eq!(got.status, "proposed");
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn accept_and_a_new_decision_reset_the_review() {
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let v = te::verify(c.conn(), &agent(), &id).unwrap();
    review::review_accept(c.conn(), &carlos(), "timeline_entry", &id, v.seq, None).unwrap();
    assert_eq!(te::list(c.conn(), None, Some("accepted")).unwrap().len(), 1);
    te::reject(c.conn(), &agent(), &id, "wrong user").unwrap();
    let e = one(&c, &id);
    assert_eq!(
        (e.status.as_str(), e.review_state.as_str()),
        ("rejected", "pending_review")
    );
    assert_eq!(e.reviewed_by, None);
}

#[test]
fn evidence_ref_splits_on_the_first_colon() {
    let r = EvidenceRef::parse("ual_events:abc:def").unwrap();
    assert_eq!(
        (r.source_table.as_str(), r.record_key.as_str()),
        ("ual_events", "abc:def")
    );
    assert!(EvidenceRef::parse("nocolon").is_err());
    assert!(EvidenceRef::parse(":k").is_err());
    assert!(EvidenceRef::parse("signins:").is_err());
}

#[test]
fn notes_attach_to_existing_targets_only() {
    let c = case_with_evidence();
    let (nid, e) = notes::add_note(
        c.conn(),
        &agent(),
        NoteTarget::parse("signins:k1").unwrap(),
        "token from VPS",
    )
    .unwrap();
    assert_eq!(
        (
            e.action.as_str(),
            e.object_type.as_str(),
            e.object_id.as_str()
        ),
        ("add_note", "annotation", nid.as_str())
    );
    assert!(
        notes::add_note(
            c.conn(),
            &agent(),
            NoteTarget::parse("finding:nope").unwrap(),
            "x"
        )
        .is_err()
    );
    assert!(
        notes::add_note(
            c.conn(),
            &agent(),
            NoteTarget::parse("entry:nope").unwrap(),
            "x"
        )
        .is_err()
    );
    assert!(
        notes::add_note(
            c.conn(),
            &agent(),
            NoteTarget::parse("ioc:nope").unwrap(),
            "x"
        )
        .is_err()
    );
    assert!(
        notes::add_note(
            c.conn(),
            &agent(),
            NoteTarget::parse("signins:nope").unwrap(),
            "x"
        )
        .is_err()
    );
    let err = notes::add_note(
        c.conn(),
        &agent(),
        NoteTarget::parse("signins:k1").unwrap(),
        "   ",
    )
    .unwrap_err();
    assert!(is_decision(&err), "{err:?}");
    let got = notes::notes_for(c.conn(), &NoteTarget::parse("signins:k1").unwrap()).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].text, "token from VPS");
    assert_eq!(got[0].actor, "agent:claude");
    assert_eq!(got[0].on_behalf_of.as_deref(), Some("analyst:carlos"));
    assert_eq!(got[0].created_at, e.ts);
    assert!(
        notes::notes_for(c.conn(), &NoteTarget::parse("signins:k2").unwrap())
            .unwrap()
            .is_empty()
    );
    assert_eq!(audit_len(&c), 1);
}

#[test]
fn notes_on_every_kind_of_target() {
    let c = case_with_evidence();
    c.conn()
        .execute_batch(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, created_by, created_at, updated_at) VALUES ('f1', 'fp1', 't1', 'R', 1, 'x', 'high', 'AiTM', 'rule', now(), now());",
        )
        .unwrap();
    let ioc = sparrow_core::case::indicators::add_indicator(
        c.conn(),
        &agent(),
        None,
        sparrow_core::case::indicators::IndicatorType::Ip,
        "203.0.113.9",
        sparrow_core::case::indicators::Verdict::Malicious,
        None,
    )
    .unwrap();
    let (entry, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let hostile = "a,b\"c\nd|e 🔥 \u{202E}x\u{0}";
    for (target, kind) in [
        ("finding:f1".to_string(), "finding"),
        (format!("ioc:{ioc}"), "indicator"),
        (format!("entry:{entry}"), "timeline_entry"),
        ("ual_events:abc:def".to_string(), "evidence"),
    ] {
        let t = NoteTarget::parse(&target).unwrap();
        let (_, e) = notes::add_note(c.conn(), &agent(), t.clone(), hostile).unwrap();
        assert_eq!(e.after.as_ref().unwrap()["object_type"], kind);
        let got = notes::notes_for(c.conn(), &t).unwrap();
        assert_eq!(got.len(), 1, "{target}");
        assert_eq!(got[0].text, hostile);
        assert_eq!(got[0].object_type, kind);
    }
    let ev_note =
        &notes::notes_for(c.conn(), &NoteTarget::parse("ual_events:abc:def").unwrap()).unwrap()[0];
    assert_eq!(
        (ev_note.source_table.as_deref(), ev_note.object_id.as_str()),
        (Some("ual_events"), "abc:def")
    );
    // Notes are not decisions: nothing to review.
    let nid = &ev_note.annotation_id;
    assert_eq!(
        review::latest_decision_seq(c.conn(), "annotation", nid).unwrap(),
        None
    );
    assert!(audit::verify(c.conn()).unwrap().ok);
}
