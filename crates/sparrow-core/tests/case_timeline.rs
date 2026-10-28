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
        end_time: None,
        event_count: None,
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
            narrative: Some(Some("from a VPS".into())),
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
        narrative: Some(Some("other".into())),
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

fn edit_title(t: &str) -> EntryEdit {
    EntryEdit {
        title: Some(t.into()),
        ..Default::default()
    }
}

#[test]
fn a_chain_of_three_discards_back_to_the_middle() {
    let c = case_with_evidence();
    let (x, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    te::verify(c.conn(), &agent(), &x).unwrap();
    let (b, _) = te::edit(c.conn(), &agent(), &x, edit_title("B")).unwrap();
    te::verify(c.conn(), &agent(), &b).unwrap();
    let (cc, _) = te::edit(c.conn(), &agent(), &b, edit_title("C")).unwrap();
    let vc = te::verify(c.conn(), &agent(), &cc).unwrap();
    assert_eq!(
        (one(&c, &x).status, one(&c, &b).status, one(&c, &cc).status),
        (
            "superseded".to_string(),
            "superseded".to_string(),
            "verified".to_string()
        )
    );
    // B is reviewed only through C while superseded.
    let b_seq = review::latest_decision_seq(c.conn(), "timeline_entry", &b)
        .unwrap()
        .unwrap();
    let err =
        review::review_accept(c.conn(), &carlos(), "timeline_entry", &b, b_seq, None).unwrap_err();
    assert!(err.to_string().contains("superseded"), "{err}");
    review::review_discard(c.conn(), &carlos(), "timeline_entry", &cc, vc.seq, None).unwrap();
    assert_eq!(
        (one(&c, &x).status, one(&c, &b).status, one(&c, &cc).status),
        (
            "superseded".to_string(),
            "verified".to_string(),
            "proposed".to_string()
        )
    );
    // B is reviewable again.
    review::review_accept(c.conn(), &carlos(), "timeline_entry", &b, b_seq, None).unwrap();
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn discarding_a_reject_restores_the_verified_entry() {
    let c = case_with_evidence();
    let two = vec![
        EvidenceRef::parse("signins:k1").unwrap(),
        EvidenceRef::parse("signins:k2").unwrap(),
    ];
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(two.clone())).unwrap();
    te::verify(c.conn(), &agent(), &id).unwrap();
    let r = te::reject(c.conn(), &agent(), &id, "duplicate").unwrap();
    review::review_discard(c.conn(), &carlos(), "timeline_entry", &id, r.seq, None).unwrap();
    let e = one(&c, &id);
    assert_eq!(e.status, "verified");
    assert_eq!(e.evidence, two);
}

#[test]
fn discarding_a_successor_propose_rejects_it_and_keeps_the_original() {
    let c = case_with_evidence();
    let (x, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    te::verify(c.conn(), &agent(), &x).unwrap();
    let (b, p) = te::edit(c.conn(), &agent(), &x, edit_title("B")).unwrap();
    review::review_discard(c.conn(), &carlos(), "timeline_entry", &b, p.seq, None).unwrap();
    assert_eq!(one(&c, &b).status, "rejected");
    assert_eq!(one(&c, &x).status, "verified");
    assert!(te::verify(c.conn(), &agent(), &b).is_err());
}

#[test]
fn discarding_a_title_edit_touches_only_the_title() {
    let c = case_with_evidence();
    let two = vec![
        EvidenceRef::parse("signins:k2").unwrap(),
        EvidenceRef::parse("ual_events:abc:def").unwrap(),
    ];
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(two)).unwrap();
    let before = one(&c, &id);
    let (_, e) = te::edit(c.conn(), &agent(), &id, edit_title("renamed")).unwrap();
    assert_eq!(
        e.before.as_ref().unwrap()["evidence"],
        e.after.as_ref().unwrap()["evidence"]
    );
    let d =
        review::review_discard(c.conn(), &carlos(), "timeline_entry", &id, e.seq, None).unwrap();
    let restored = d.after.as_ref().unwrap()["restored"]
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(restored.keys().collect::<Vec<_>>(), ["title"]);
    let after = one(&c, &id);
    assert_eq!(
        (
            &after.title,
            &after.phase,
            after.event_time,
            &after.narrative,
            &after.evidence
        ),
        (
            &before.title,
            &before.phase,
            before.event_time,
            &before.narrative,
            &before.evidence
        )
    );
}

#[test]
fn a_failed_revert_changes_nothing() {
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let edit = EntryEdit {
        title: Some("changed".into()),
        evidence: Some(vec![EvidenceRef::parse("signins:k2").unwrap()]),
        ..Default::default()
    };
    let (_, e) = te::edit(c.conn(), &agent(), &id, edit).unwrap();
    let entries = audit_len(&c);
    te::test_hooks::fail_after_evidence_delete(true);
    let err = review::review_discard(c.conn(), &carlos(), "timeline_entry", &id, e.seq, None)
        .unwrap_err();
    te::test_hooks::fail_after_evidence_delete(false);
    assert!(err.to_string().contains("injected"), "{err}");
    let got = one(&c, &id);
    assert_eq!(got.title, "changed");
    assert_eq!(
        got.evidence,
        vec![EvidenceRef::parse("signins:k2").unwrap()]
    );
    assert_eq!(got.review_state, "pending_review");
    assert_eq!(audit_len(&c), entries);
    // Without the failure the same discard works.
    review::review_discard(c.conn(), &carlos(), "timeline_entry", &id, e.seq, None).unwrap();
    assert_eq!(one(&c, &id).evidence, ev());
}

#[test]
fn a_narrative_can_be_cleared() {
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let (_, e) = te::edit(
        c.conn(),
        &agent(),
        &id,
        EntryEdit {
            narrative: Some(None),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(one(&c, &id).narrative, None);
    // Clearing an empty narrative changes nothing.
    assert!(
        te::edit(
            c.conn(),
            &agent(),
            &id,
            EntryEdit {
                narrative: Some(None),
                ..Default::default()
            }
        )
        .is_err()
    );
    review::review_discard(c.conn(), &carlos(), "timeline_entry", &id, e.seq, None).unwrap();
    assert_eq!(one(&c, &id).narrative.as_deref(), Some("replayed session"));
}

#[test]
fn text_lengths_are_capped_before_any_write() {
    use sparrow_core::case::text::{MAX_TEXT_BYTES, MAX_TITLE_CHARS};
    let c = case_with_evidence();
    // At the cap: accepted (multi-byte title counts characters).
    let mut e = new_entry(ev());
    e.title = "é".repeat(MAX_TITLE_CHARS);
    e.narrative = Some("n".repeat(MAX_TEXT_BYTES));
    let (id, _) = te::propose(c.conn(), &agent(), e).unwrap();
    let n = audit_len(&c);
    let mut long_title = new_entry(ev());
    long_title.title = "t".repeat(MAX_TITLE_CHARS + 1);
    assert!(is_decision(
        &te::propose(c.conn(), &agent(), long_title).unwrap_err()
    ));
    let mut long_narrative = new_entry(ev());
    long_narrative.narrative = Some("é".repeat(MAX_TEXT_BYTES / 2 + 1));
    assert!(is_decision(
        &te::propose(c.conn(), &agent(), long_narrative).unwrap_err()
    ));
    let too_long = "r".repeat(MAX_TEXT_BYTES + 1);
    assert!(is_decision(
        &te::reject(c.conn(), &agent(), &id, &too_long).unwrap_err()
    ));
    assert!(is_decision(
        &te::edit(
            c.conn(),
            &agent(),
            &id,
            EntryEdit {
                narrative: Some(Some(too_long.clone())),
                ..Default::default()
            }
        )
        .unwrap_err()
    ));
    assert!(is_decision(
        &notes::add_note(
            c.conn(),
            &agent(),
            NoteTarget::parse("signins:k1").unwrap(),
            &too_long
        )
        .unwrap_err()
    ));
    c.conn()
        .execute_batch(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, created_by, created_at, updated_at) VALUES ('f1', 'fp1', 't1', 'R', 1, 'x', 'high', 'AiTM', 'rule', now(), now());",
        )
        .unwrap();
    use sparrow_core::case::write::{FindingStatus, set_finding_status};
    assert!(is_decision(
        &set_finding_status(
            c.conn(),
            &agent(),
            "f1",
            FindingStatus::Confirmed,
            Some(&too_long)
        )
        .unwrap_err()
    ));
    assert!(is_decision(
        &review::review_accept(
            c.conn(),
            &carlos(),
            "timeline_entry",
            &id,
            1,
            Some(&too_long)
        )
        .unwrap_err()
    ));
    assert_eq!(audit_len(&c), n);
    // Text is stored as given.
    let raw = "  line\none\t\u{1b}[31m  ";
    notes::add_note(
        c.conn(),
        &agent(),
        NoteTarget::parse("signins:k1").unwrap(),
        raw,
    )
    .unwrap();
    assert_eq!(
        notes::notes_for(c.conn(), &NoteTarget::parse("signins:k1").unwrap()).unwrap()[0].text,
        raw
    );
}

#[test]
fn display_safe_escapes_control_characters() {
    use sparrow_core::case::text::display_safe;
    assert_eq!(display_safe("plain é 🔥"), "plain é 🔥");
    assert_eq!(display_safe("a\nb\tc"), "a\nb\tc");
    assert_eq!(display_safe("\u{1b}[31mred"), "\\u{001B}[31mred");
    assert_eq!(
        display_safe("nul\u{0}x\r\u{7f}"),
        "nul\\u{0000}x\\u{000D}\\u{007F}"
    );
    assert_eq!(display_safe("c1\u{9b}"), "c1\\u{009B}");
}

#[test]
fn display_escapes_format_characters_and_single_lines_escape_newlines() {
    use sparrow_core::case::text::{display_safe, display_safe_line};
    // Bidi overrides and isolates, zero-width characters and the BOM are escaped in both forms.
    for (c, hex) in [
        ('\u{202E}', "202E"),
        ('\u{2066}', "2066"),
        ('\u{200B}', "200B"),
        ('\u{200F}', "200F"),
        ('\u{FEFF}', "FEFF"),
        ('\u{E0041}', "E0041"),
    ] {
        let want = format!("a\\u{{{hex}}}b");
        assert_eq!(display_safe(&format!("a{c}b")), want);
        assert_eq!(display_safe_line(&format!("a{c}b")), want);
    }
    // Blocks keep newlines and tabs; a single line keeps tabs only.
    assert_eq!(display_safe("one\ntwo\tx"), "one\ntwo\tx");
    assert_eq!(
        display_safe_line("one\ntwo\tx\r"),
        "one\\u{000A}two\tx\\u{000D}"
    );
    // Ordinary text, accents and emoji pass through.
    assert_eq!(display_safe_line("Ünïcødé 🔥 שלום"), "Ünïcødé 🔥 שלום");
}

// ---- grouped entries and analyst-verified entries (investigate tabs, task 5)

fn at(h: u32, m: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 3, h, m, 0).unwrap()
}

/// `n` more evidence records, `signins:g0` .. `signins:g{n-1}`, sighted in the case's one source file.
fn add_group_evidence(c: &Case, n: u32) -> Vec<EvidenceRef> {
    c.conn()
        .execute(
            &format!(
                "INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end, \
                                             byte_offset, byte_length, raw_sha256) \
                 SELECT 'signins', 'g' || i, 1, 100 + i, 10 + i, 10 + i, 1000 + i, 1, 'rg' || i \
                 FROM range({n}) t(i)"
            ),
            [],
        )
        .unwrap();
    (0..n)
        .map(|i| EvidenceRef::parse(&format!("signins:g{i}")).unwrap())
        .collect()
}

fn grouped(evidence: Vec<EvidenceRef>) -> NewEntry {
    NewEntry {
        end_time: Some(at(11, 30)),
        event_count: Some(evidence.len() as u64),
        event_time: at(9, 0),
        title: "Password spray from one relay".into(),
        narrative: None,
        phase: Phase::InitialAccess,
        tenant_key: Some("t1".into()),
        evidence,
    }
}

#[test]
fn grouped_entry_round_trips_end_and_count() {
    let c = case_with_evidence();
    let refs = add_group_evidence(&c, 5000);
    let (id, p) = te::propose(c.conn(), &agent(), grouped(refs.clone())).unwrap();
    assert_eq!(
        count(
            &c,
            &format!("SELECT count(*) FROM timeline_entry_evidence WHERE entry_id = '{id}'")
        ),
        5000
    );
    let got = one(&c, &id);
    assert_eq!(got.event_time, at(9, 0));
    assert_eq!(got.end_time, Some(at(11, 30)));
    assert_eq!(got.event_count, Some(5000));
    assert_eq!(got.evidence.len(), 5000);
    // the audit row's after state carries the span
    assert_eq!(
        p.after.as_ref().unwrap()["end_time"],
        "2026-08-03T11:30:00.000000Z"
    );
    assert_eq!(p.after.as_ref().unwrap()["event_count"], 5000);
    // an ordinary entry has neither, in the entry and in its audit state
    let (plain, p) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let got = one(&c, &plain);
    assert_eq!((got.end_time, got.event_count), (None, None));
    assert!(p.after.as_ref().unwrap().get("end_time").is_none());
    assert!(p.after.as_ref().unwrap().get("event_count").is_none());
    // and the JSON of an entry names them
    let j = serde_json::to_value(one(&c, &id)).unwrap();
    assert_eq!(j["end_time"], "2026-08-03T11:30:00.000000Z");
    assert_eq!(j["event_count"], 5000);
    // the analyst's one-step create takes the same 5,000 rows
    let mut again = grouped(refs);
    again.title = "Same spray, verified".into();
    let (vid, rows) = te::create_verified(c.conn(), &carlos(), again).unwrap();
    assert_eq!(rows.len(), 2);
    let got = one(&c, &vid);
    assert_eq!(
        (got.status.as_str(), got.evidence.len(), got.event_count),
        ("verified", 5000, Some(5000))
    );
}

fn count(c: &Case, sql: &str) -> i64 {
    c.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn a_span_must_end_after_it_starts_and_cover_an_event() {
    let c = case_with_evidence();
    let before = audit_len(&c);
    let mut e = new_entry(ev());
    e.end_time = Some(at(8, 59));
    let err = te::propose(c.conn(), &agent(), e).unwrap_err();
    assert!(
        is_decision(&err) && err.to_string().contains("cannot end"),
        "{err}"
    );
    let mut e = new_entry(ev());
    e.event_count = Some(0);
    let err = te::propose(c.conn(), &agent(), e).unwrap_err();
    assert!(
        is_decision(&err) && err.to_string().contains("at least one event"),
        "{err}"
    );
    // an end equal to the start is a valid span
    let mut e = new_entry(ev());
    e.end_time = Some(at(9, 0));
    te::propose(c.conn(), &agent(), e).unwrap();
    assert_eq!(audit_len(&c), before + 1);
    // an edit is held to the same rules
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let bad = EntryEdit {
        end_time: Some(Some(at(8, 0))),
        ..Default::default()
    };
    assert!(is_decision(
        &te::edit(c.conn(), &agent(), &id, bad).unwrap_err()
    ));
    let bad = EntryEdit {
        event_count: Some(Some(0)),
        ..Default::default()
    };
    assert!(is_decision(
        &te::edit(c.conn(), &agent(), &id, bad).unwrap_err()
    ));
}

#[test]
fn editing_a_grouped_entry_carries_or_changes_the_span() {
    let c = case_with_evidence();
    let refs = add_group_evidence(&c, 3);
    let (id, _) = te::create_verified(c.conn(), &carlos(), grouped(refs)).unwrap();
    // a title edit of a verified entry proposes a successor that keeps the span
    let (s1, _) = te::edit(
        c.conn(),
        &carlos().as_actor(),
        &id,
        EntryEdit {
            title: Some("Spray, confirmed".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let got = one(&c, &s1);
    assert_eq!(got.supersedes.as_deref(), Some(id.as_str()));
    assert_eq!((got.end_time, got.event_count), (Some(at(11, 30)), Some(3)));
    // a span edit changes it, and an edit of only the count counts as a change
    te::verify(c.conn(), &carlos().as_actor(), &s1).unwrap();
    let (s2, _) = te::edit(
        c.conn(),
        &carlos().as_actor(),
        &s1,
        EntryEdit {
            end_time: Some(Some(at(12, 0))),
            event_count: Some(Some(40)),
            ..Default::default()
        },
    )
    .unwrap();
    let got = one(&c, &s2);
    assert_eq!((got.end_time, got.event_count), (Some(at(12, 0)), Some(40)));
    assert_eq!(got.title, "Spray, confirmed");
    // the same edit again changes nothing
    te::verify(c.conn(), &carlos().as_actor(), &s2).unwrap();
    let same = EntryEdit {
        event_count: Some(Some(40)),
        ..Default::default()
    };
    assert!(is_decision(
        &te::edit(c.conn(), &carlos().as_actor(), &s2, same).unwrap_err()
    ));
    // the span can be cleared
    let (s3, _) = te::edit(
        c.conn(),
        &carlos().as_actor(),
        &s2,
        EntryEdit {
            end_time: Some(None),
            event_count: Some(None),
            ..Default::default()
        },
    )
    .unwrap();
    let got = one(&c, &s3);
    assert_eq!((got.end_time, got.event_count), (None, None));
}

#[test]
fn discarding_an_edit_restores_the_span() {
    let c = case_with_evidence();
    let refs = add_group_evidence(&c, 3);
    let (id, _) = te::propose(c.conn(), &agent(), grouped(refs)).unwrap();
    let (_, e) = te::edit(
        c.conn(),
        &agent(),
        &id,
        EntryEdit {
            end_time: Some(None),
            event_count: Some(Some(2)),
            ..Default::default()
        },
    )
    .unwrap();
    let got = one(&c, &id);
    assert_eq!((got.end_time, got.event_count), (None, Some(2)));
    review::review_discard(c.conn(), &carlos(), "timeline_entry", &id, e.seq, None).unwrap();
    let got = one(&c, &id);
    assert_eq!((got.end_time, got.event_count), (Some(at(11, 30)), Some(3)));
}

#[test]
fn create_verified_is_verified_with_two_audit_rows() {
    let c = case_with_evidence();
    let before = audit_len(&c);
    let (id, rows) = te::create_verified(c.conn(), &carlos(), new_entry(ev())).unwrap();
    assert_eq!(audit_len(&c), before + 2);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter().map(|r| r.action.as_str()).collect::<Vec<_>>(),
        ["propose_entry", "verify_entry"]
    );
    assert!(
        rows.iter()
            .all(|r| r.object_type == "timeline_entry" && r.object_id == id)
    );
    assert!(
        rows.iter()
            .all(|r| r.actor == "analyst:carlos" && r.on_behalf_of.is_none())
    );
    assert_eq!(rows[1].seq, rows[0].seq + 1);
    assert_eq!(rows[0].after.as_ref().unwrap()["status"], "proposed");
    assert_eq!(rows[1].after.as_ref().unwrap()["status"], "verified");
    assert_eq!(rows[1].before.as_ref().unwrap()["status"], "proposed");
    // the log holds exactly those two rows, in order, and the chain verifies
    let log = audit::log(c.conn(), Some(("timeline_entry", &id))).unwrap();
    assert_eq!(
        log.iter().map(|r| r.seq).collect::<Vec<_>>(),
        [rows[0].seq, rows[1].seq]
    );
    assert!(audit::verify(c.conn()).unwrap().ok);
    // verified and reviewed as made: nothing for the Review queue
    let got = one(&c, &id);
    assert_eq!(got.status, "verified");
    assert_eq!(got.decided_by, "analyst:carlos");
    assert_eq!(got.review_state, "accepted");
    assert_eq!(got.reviewed_by.as_deref(), Some("analyst:carlos"));
    assert!(review::pending(c.conn()).unwrap().is_empty());
    assert_eq!(got.evidence, ev());
}

#[test]
fn create_verified_that_cannot_verify_writes_nothing() {
    let c = case_with_evidence();
    let before = audit_len(&c);
    // no evidence: the verify step fails, so the propose is rolled back with it
    let err = te::create_verified(c.conn(), &carlos(), new_entry(vec![])).unwrap_err();
    assert!(
        is_decision(&err) && err.to_string().contains("no evidence"),
        "{err}"
    );
    assert_eq!(audit_len(&c), before);
    assert_eq!(count(&c, "SELECT count(*) FROM timeline_entries"), 0);
    // evidence that is not in the case fails the propose step
    let ghost = vec![EvidenceRef::parse("signins:nope").unwrap()];
    assert!(is_decision(
        &te::create_verified(c.conn(), &carlos(), new_entry(ghost)).unwrap_err()
    ));
    assert_eq!(audit_len(&c), before);
    assert_eq!(count(&c, "SELECT count(*) FROM timeline_entries"), 0);
}

#[test]
fn agent_cannot_create_verified() {
    // `create_verified` takes a `Reviewer`, and the only way to make one is `Reviewer::analyst`, which refuses an
    // `agent:` identity; an `Actor` does not convert to a `Reviewer` (see the compile_fail doctest on the function).
    assert!(Reviewer::analyst("agent:claude").is_err());
    assert!(Reviewer::analyst("").is_err());
    // an agent's own entries stay proposed and pending review
    let c = case_with_evidence();
    let (id, _) = te::propose(c.conn(), &agent(), new_entry(ev())).unwrap();
    let got = one(&c, &id);
    assert_eq!(
        (got.status.as_str(), got.review_state.as_str()),
        ("proposed", "pending_review")
    );
}

#[test]
fn default_phase_table() {
    let p =
        |cats: &[&str]| te::default_phase(&cats.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    // one assertion per event_category value, so a new category is a deliberate decision
    let table = [
        ("auth", Phase::InitialAccess),
        ("audit_tamper", Phase::DefenseEvasion),
        ("mail_rule", Phase::Persistence),
        ("forwarding", Phase::Persistence),
        ("config_change", Phase::Persistence),
        ("app_consent", Phase::Persistence),
        ("app_credential", Phase::Persistence),
        ("mfa_change", Phase::Persistence),
        ("role_change", Phase::Persistence),
        ("permission", Phase::Persistence),
        ("mail_read", Phase::Collection),
        ("file_access", Phase::Collection),
        ("file_download", Phase::Collection),
        ("ediscovery", Phase::Collection),
        ("mail_flow", Phase::Exfiltration),
        ("mail_send", Phase::Exfiltration),
        ("file_share", Phase::Exfiltration),
        ("lure_staging", Phase::Recon),
        ("search", Phase::Recon),
        ("device", Phase::Recon),
        ("other", Phase::Recon),
    ];
    assert_eq!(table.len(), 21, "every event_category value is listed");
    for (c, want) in table {
        assert_eq!(p(&[c]), want, "{c}");
    }
    // not categories: recon, as is nothing at all
    for c in ["not_a_category", "AUTH", ""] {
        assert_eq!(p(&[c]), Phase::Recon, "{c:?}");
    }
    assert_eq!(p(&[]), Phase::Recon);
    // first match in order wins over any later rule, whatever the input order
    assert_eq!(
        p(&[
            "file_share",
            "mail_read",
            "mail_rule",
            "audit_tamper",
            "auth"
        ]),
        Phase::InitialAccess
    );
    assert_eq!(
        p(&["file_share", "mail_read", "mail_rule", "audit_tamper"]),
        Phase::DefenseEvasion
    );
    assert_eq!(
        p(&["file_share", "mail_read", "mail_rule"]),
        Phase::Persistence
    );
    assert_eq!(p(&["file_share", "mail_read"]), Phase::Collection);
    assert_eq!(p(&["other", "mail_send"]), Phase::Exfiltration);
}

#[test]
fn default_phase_names_cover_the_event_category_enum() {
    // The enum in the migration is exactly the 21 names of the phase table, and each real value maps to the phase
    // the table gives it.
    let expected: [(&str, Phase); 21] = [
        ("app_consent", Phase::Persistence),
        ("app_credential", Phase::Persistence),
        ("audit_tamper", Phase::DefenseEvasion),
        ("auth", Phase::InitialAccess),
        ("config_change", Phase::Persistence),
        ("device", Phase::Recon),
        ("ediscovery", Phase::Collection),
        ("file_access", Phase::Collection),
        ("file_download", Phase::Collection),
        ("file_share", Phase::Exfiltration),
        ("forwarding", Phase::Persistence),
        ("lure_staging", Phase::Recon),
        ("mail_flow", Phase::Exfiltration),
        ("mail_read", Phase::Collection),
        ("mail_rule", Phase::Persistence),
        ("mail_send", Phase::Exfiltration),
        ("mfa_change", Phase::Persistence),
        ("other", Phase::Recon),
        ("permission", Phase::Persistence),
        ("role_change", Phase::Persistence),
        ("search", Phase::Recon),
    ];
    let c = Case::in_memory().unwrap();
    let mut stmt = c
        .conn()
        .prepare("SELECT unnest(enum_range(NULL::event_category))::VARCHAR ORDER BY 1")
        .unwrap();
    let real: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        real,
        expected
            .iter()
            .map(|(n, _)| n.to_string())
            .collect::<Vec<_>>(),
        "the enum and the table list the same names"
    );
    for (name, want) in expected {
        assert_eq!(te::default_phase(&[name.to_string()]), want, "{name}");
    }
}

#[test]
fn fifty_thousand_refs_across_three_tables_are_checked_and_stored_set_based() {
    let c = case_with_evidence();
    c.conn()
        .execute(
            "INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end, \
                                         byte_offset, byte_length, raw_sha256) \
             SELECT ['signins', 'ual_events', 'audit_logs'][1 + i % 3], 'bulk' || i, 1, 1000 + i, 1, 1, i, 1, 'rb' || i \
             FROM range(50000) t(i)",
            [],
        )
        .unwrap();
    let refs: Vec<EvidenceRef> = (0..50_000)
        .map(|i| {
            let t = ["signins", "ual_events", "audit_logs"][i % 3];
            EvidenceRef::parse(&format!("{t}:bulk{i}")).unwrap()
        })
        .collect();
    let started = std::time::Instant::now();
    let (id, rows) = te::create_verified(c.conn(), &carlos(), grouped(refs.clone())).unwrap();
    eprintln!("create_verified with 50,000 refs: {:?}", started.elapsed());
    assert_eq!(rows.len(), 2);
    assert_eq!(
        count(
            &c,
            &format!("SELECT count(*) FROM timeline_entry_evidence WHERE entry_id = '{id}'")
        ),
        50_000
    );
    assert_eq!(
        count(
            &c,
            &format!(
                "SELECT count(DISTINCT source_table) FROM timeline_entry_evidence WHERE entry_id = '{id}'"
            )
        ),
        3
    );
    assert_eq!(one(&c, &id).event_count, Some(50_000));
    // one missing ref anywhere in the set refuses the whole call and writes nothing; the first missing one in
    // (table, key) order is named, and the staging table is gone afterwards
    let before = audit_len(&c);
    let mut bad = refs.clone();
    bad[40_000] = EvidenceRef::parse("signins:zz-missing").unwrap();
    bad[10] = EvidenceRef::parse("audit_logs:aa-missing").unwrap();
    let mut e = grouped(bad);
    e.title = "has ghosts".into();
    let err = te::create_verified(c.conn(), &carlos(), e).unwrap_err();
    assert!(
        is_decision(&err) && err.to_string().contains("audit_logs:aa-missing"),
        "{err}"
    );
    assert_eq!(audit_len(&c), before);
    assert_eq!(count(&c, "SELECT count(*) FROM timeline_entries"), 1);
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM duckdb_tables() WHERE table_name = '_evidence_check'"
        ),
        0
    );
}
