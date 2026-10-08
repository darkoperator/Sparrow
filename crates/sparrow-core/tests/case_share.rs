#[path = "common/synth.rs"]
mod synth;

use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::indicators::{IndicatorType, Verdict, add_indicator, remove_indicator};
use sparrow_core::case::notes::{NoteTarget, add_note};
use sparrow_core::case::share::{self, Item};
use sparrow_core::case::timeline_entries::{self as te, NewEntry, Phase};
use sparrow_core::case::write::{FindingStatus as S, set_finding_status};
use sparrow_core::case::{audit, review};
use sparrow_core::{Case, Error};
use sparrow_synth::options::PsEdition;
use synth::{count, text};

/// Two private copies of the same detected synthetic case: same evidence, same findings, same case id.
fn two_copies() -> (Case, Case) {
    (
        synth::builtin_detected("bec-aitm", PsEdition::Ps7).case,
        synth::builtin_detected("bec-aitm", PsEdition::Ps7).case,
    )
}

fn first_finding(c: &Case) -> String {
    text(
        c,
        "SELECT finding_id FROM findings ORDER BY finding_id LIMIT 1",
    )
}

fn two_findings(c: &Case) -> (String, String) {
    (
        text(
            c,
            "SELECT finding_id FROM findings ORDER BY finding_id LIMIT 1",
        ),
        text(
            c,
            "SELECT finding_id FROM findings ORDER BY finding_id LIMIT 1 OFFSET 1",
        ),
    )
}

fn status_of(c: &Case, fid: &str) -> String {
    text(
        c,
        &format!("SELECT CAST(status AS VARCHAR) FROM findings WHERE finding_id = '{fid}'"),
    )
}

/// An evidence record of the case (for a timeline entry), the first by table and key.
fn first_evidence(c: &Case) -> String {
    text(
        c,
        "SELECT table_name || ':' || record_key FROM record_sources ORDER BY table_name, record_key LIMIT 1",
    )
}

#[test]
fn export_holds_only_reviewed_work_with_evidence_identity() {
    let (a, _b) = two_copies();
    let fid = first_finding(&a);
    let agent = Actor::agent("claude", Some("carlos")).unwrap();
    let carlos = Reviewer::analyst("carlos").unwrap();
    // pending agent decision: not exported
    set_finding_status(a.conn(), &agent, &fid, S::InReview, None).unwrap();
    let b0 = share::export(a.conn(), &carlos).unwrap();
    assert!(b0.items.iter().all(|i| !matches!(i, Item::Finding { .. })));
    // accepted: exported
    let seq = review::latest_decision_seq(a.conn(), "finding", &fid)
        .unwrap()
        .unwrap();
    review::review_accept(a.conn(), &carlos, "finding", &fid, seq, None).unwrap();
    // analyst decision and analyst note: exported; agent note: not
    add_indicator(
        a.conn(),
        &carlos.as_actor(),
        None,
        IndicatorType::Ip,
        "203.0.113.7",
        Verdict::Malicious,
        Some("relay"),
    )
    .unwrap();
    add_note(
        a.conn(),
        &carlos.as_actor(),
        NoteTarget::Finding(fid.clone()),
        "seen",
    )
    .unwrap();
    // the same note twice is one item (resulting state, one key)
    add_note(
        a.conn(),
        &carlos.as_actor(),
        NoteTarget::Finding(fid.clone()),
        "seen",
    )
    .unwrap();
    add_note(a.conn(), &agent, NoteTarget::Finding(fid.clone()), "agent").unwrap();
    let audit_rows = count(&a, "SELECT count(*) FROM audit_trail");
    let b = share::export(a.conn(), &carlos).unwrap();
    assert_eq!(
        count(&a, "SELECT count(*) FROM audit_trail"),
        audit_rows,
        "export writes nothing"
    );
    assert_eq!(b.format, share::FORMAT);
    assert_eq!(b.analyst, "analyst:carlos");
    assert_eq!(b.source_case_id, audit::case_id(a.conn()).unwrap());
    let chain = audit::verify(a.conn()).unwrap();
    assert_eq!(b.source_audit_head.seq, chain.entries);
    assert_eq!(b.source_audit_head.hash, chain.head_hash);
    assert!(b.items.contains(&Item::Finding {
        finding_id: fid.clone(),
        status: "in_review".into(),
        disposition_reason: None
    }));
    assert!(b.items.contains(&Item::Indicator {
        tenant_key: None,
        ioc_type: "ip".into(),
        value: "203.0.113.7".into(),
        verdict: "malicious".into(),
        note: Some("relay".into()),
        active: true,
    }));
    assert!(b.items.contains(&Item::Note {
        target: format!("finding:{fid}"),
        text: "seen".into()
    }));
    assert!(
        !b.items
            .iter()
            .any(|i| matches!(i, Item::Note { text, .. } if text == "agent"))
    );
    assert_eq!(
        count(
            &a,
            "SELECT count(*) FROM annotations WHERE actor = 'analyst:carlos' AND text = 'seen'"
        ),
        2
    );
    assert_eq!(
        b.items
            .iter()
            .filter(|i| matches!(i, Item::Note { text, .. } if text == "seen"))
            .count(),
        1
    );
    let keys: std::collections::BTreeSet<String> = b.items.iter().map(Item::key).collect();
    assert_eq!(keys.len(), b.items.len(), "item keys are unique");
    let ev = share::evidence_of(a.conn()).unwrap();
    assert_eq!(b.evidence, ev);
    assert!(!ev.source_files.is_empty() && ev.source_files.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(
        ev.source_files.len() as i64,
        count(
            &a,
            "SELECT count(DISTINCT sha256) FROM source_files WHERE CAST(status AS VARCHAR) = 'parsed'"
        )
    );
    assert!(!ev.rules.is_empty() && ev.rules.windows(2).all(|w| w[0] < w[1]));
    assert!(
        ev.rules
            .iter()
            .all(|r| r.starts_with("SPW-") && r.contains(':'))
    );
    let (bytes, sha) = share::to_bytes(&b).unwrap();
    assert_eq!(sha.len(), 64);
    let back: share::Bundle = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, b);
}

#[test]
fn export_holds_reviewed_entries_and_removed_indicators() {
    let (a, _b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let agent = Actor::agent("claude", None).unwrap();
    let ev = first_evidence(&a);
    let entry = |title: &str| NewEntry {
        tenant_key: None,
        event_time: chrono::DateTime::from_timestamp(1_785_000_000, 0).unwrap(),
        title: title.into(),
        narrative: Some("from the sign-in log".into()),
        phase: Phase::InitialAccess,
        evidence: vec![te::EvidenceRef::parse(&ev).unwrap()],
    };
    // verified by the analyst: exported; proposed only: not; agent-verified, unreviewed: not
    let (verified, _) =
        te::propose(a.conn(), &ann.as_actor(), entry("Sign-in from relay")).unwrap();
    te::verify(a.conn(), &ann.as_actor(), &verified).unwrap();
    te::propose(a.conn(), &ann.as_actor(), entry("Still a proposal")).unwrap();
    let (by_agent, _) = te::propose(a.conn(), &agent, entry("Agent entry")).unwrap();
    te::verify(a.conn(), &agent, &by_agent).unwrap();
    // removed by the analyst: exported as inactive
    let id = add_indicator(
        a.conn(),
        &ann.as_actor(),
        Some("t1"),
        IndicatorType::Upn,
        "user@example.test",
        Verdict::Suspicious,
        None,
    )
    .unwrap();
    assert!(remove_indicator(a.conn(), &ann.as_actor(), &id).unwrap());
    let b = share::export(a.conn(), &ann).unwrap();
    let entries: Vec<&Item> = b
        .items
        .iter()
        .filter(|i| matches!(i, Item::TimelineEntry { .. }))
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    let Item::TimelineEntry {
        entry_id,
        status,
        evidence,
        event_time,
        phase,
        narrative,
        ..
    } = entries[0]
    else {
        unreachable!()
    };
    assert_eq!(entry_id, &verified);
    assert_eq!(status, "verified");
    assert_eq!(evidence, &vec![ev]);
    assert_eq!(event_time, "2026-07-25T17:20:00.000000Z");
    assert_eq!(phase, "initial_access");
    assert_eq!(narrative.as_deref(), Some("from the sign-in log"));
    assert!(b.items.contains(&Item::Indicator {
        tenant_key: Some("t1".into()),
        ioc_type: "upn".into(),
        value: "user@example.test".into(),
        verdict: "suspicious".into(),
        note: None,
        active: false,
    }));
}

#[test]
fn export_refuses_a_broken_audit_chain() {
    let (a, _b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    set_finding_status(
        a.conn(),
        &ann.as_actor(),
        &first_finding(&a),
        S::Confirmed,
        Some("r"),
    )
    .unwrap();
    a.conn()
        .execute_batch("UPDATE audit_trail SET reason = 'forged' WHERE seq = (SELECT max(seq) FROM audit_trail)")
        .unwrap();
    let e = share::export(a.conn(), &ann).unwrap_err();
    assert!(
        matches!(&e, sparrow_core::Error::Invalid(m) if m.contains("audit chain")),
        "{e}"
    );
}

#[test]
fn item_keys_are_stable() {
    let f = Item::Finding {
        finding_id: "f1".into(),
        status: "new".into(),
        disposition_reason: None,
    };
    assert_eq!(f.key(), "finding:f1");
    let i = |t: Option<&str>| Item::Indicator {
        tenant_key: t.map(String::from),
        ioc_type: "ip".into(),
        value: "203.0.113.7".into(),
        verdict: "malicious".into(),
        note: None,
        active: true,
    };
    assert_eq!(i(None).key(), r#"indicator:[null,"ip","203.0.113.7"]"#);
    assert_eq!(
        i(Some("t1")).key(),
        r#"indicator:["t1","ip","203.0.113.7"]"#
    );
    // no collisions: a missing tenant vs a tenant named "-", and '|' inside the fields
    assert_ne!(i(None).key(), i(Some("-")).key());
    let iv = |t: &str, v: &str| Item::Indicator {
        tenant_key: Some(t.into()),
        ioc_type: "ip".into(),
        value: v.into(),
        verdict: "malicious".into(),
        note: None,
        active: true,
    };
    assert_ne!(iv("a|ip", "x").key(), iv("a", "ip|x").key());
    let e = Item::TimelineEntry {
        entry_id: "e1".into(),
        tenant_key: None,
        event_time: "x".into(),
        title: "t".into(),
        narrative: None,
        phase: "recon".into(),
        status: "verified".into(),
        evidence: vec![],
        supersedes: vec![],
    };
    assert_eq!(e.key(), "timeline_entry:e1");
    let n = |target: &str, text: &str| Item::Note {
        target: target.into(),
        text: text.into(),
    };
    let k = n("finding:f1", "seen").key();
    assert!(
        k.starts_with("note:") && k.len() == "note:".len() + 16,
        "{k}"
    );
    assert_eq!(k, n("finding:f1", "seen").key());
    assert_ne!(k, n("finding:f1", "seen!").key());
    assert_ne!(k, n("finding:f2", "seen").key());
}

#[test]
fn note_target_text_round_trips() {
    for s in [
        "finding:f1",
        "entry:e1",
        "ioc:abc",
        "ual_events:k:with:colons",
    ] {
        assert_eq!(NoteTarget::parse(s).unwrap().text(), s);
    }
}

#[test]
fn bundle_rejects_unknown_fields() {
    let s = r#"{"format":1,"exported_at":"x","analyst":"analyst:a","source_case_id":"c","source_audit_head":{"seq":1,"hash":null},
               "evidence":{"source_files":[],"rules":[]},"items":[],"extra":1}"#;
    assert!(serde_json::from_str::<share::Bundle>(s).is_err());
    let item = r#"{"format":1,"exported_at":"x","analyst":"analyst:a","source_case_id":"c","source_audit_head":{"seq":1,"hash":null},
               "evidence":{"source_files":[],"rules":[]},"items":[{"kind":"note","target":"finding:f","text":"t","x":1}]}"#;
    assert!(serde_json::from_str::<share::Bundle>(item).is_err());
}

#[test]
fn migration_21_creates_imported_proposals() {
    let c = Case::in_memory().unwrap();
    assert_eq!(c.schema_version().unwrap(), 21);
    assert_eq!(count(&c, "SELECT count(*) FROM imported_proposals"), 0);
}

#[test]
fn to_bytes_refuses_a_bundle_over_the_limit() {
    let bundle = |text: String| share::Bundle {
        format: share::FORMAT,
        exported_at: "2026-10-07T00:00:00.000000Z".into(),
        analyst: "analyst:ann".into(),
        source_case_id: "c".into(),
        source_audit_head: share::Head { seq: 0, hash: None },
        evidence: share::Evidence {
            source_files: vec![],
            rules: vec![],
        },
        items: vec![Item::Note {
            target: "finding:f1".into(),
            text,
        }],
    };
    let e = share::to_bytes(&bundle("a".repeat(share::MAX_BUNDLE_BYTES))).unwrap_err();
    assert!(
        matches!(&e, sparrow_core::Error::Invalid(m) if m.contains("limited to") && m.contains(&share::MAX_BUNDLE_BYTES.to_string())),
        "{e}"
    );
    // just under the limit is fine
    let (bytes, _) = share::to_bytes(&bundle("a".repeat(share::MAX_BUNDLE_BYTES - 1024))).unwrap();
    assert!(bytes.len() <= share::MAX_BUNDLE_BYTES);
}

// ---------------------------------------------------------------- import, accept, discard (Task 3)

#[test]
fn round_trip_accept_applies_as_b_analyst_decision() {
    let (a, b) = two_copies();
    let fid = first_finding(&a);
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    set_finding_status(
        a.conn(),
        &ann.as_actor(),
        &fid,
        S::Confirmed,
        Some("AiTM relay"),
    )
    .unwrap();
    let (bytes, sha) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let audit_before = count(&b, "SELECT count(*) FROM audit_trail");
    let s = share::import(b.conn(), &bob, &bytes).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts, s.missing), (1, 0, 0, 0));
    assert_eq!(s.bundle_sha256, sha);
    assert_eq!(s.analyst, "analyst:ann");
    assert!(!s.already_imported);
    assert!(s.rules_only_in_bundle.is_empty() && s.rules_only_here.is_empty());
    // proposals change nothing but the proposal table and one audit row
    assert_eq!(status_of(&b, &fid), "new");
    assert_eq!(
        count(&b, "SELECT count(*) FROM audit_trail"),
        audit_before + 1
    );
    assert_eq!(
        text(
            &b,
            "SELECT action FROM audit_trail ORDER BY seq DESC LIMIT 1"
        ),
        "import_share"
    );
    let p = share::proposals(b.conn()).unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].item_key, format!("finding:{fid}"));
    assert_eq!(
        (p[0].classification.as_str(), p[0].state.as_str()),
        ("new", "open")
    );
    assert_eq!(p[0].current, None);
    let entries = share::accept(b.conn(), &bob, &sha, &p[0].item_key).unwrap();
    assert_eq!(entries[0].actor, "analyst:bob");
    assert_eq!(entries[0].action, "set_status");
    assert!(
        entries[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("analyst:ann")
    );
    assert!(entries[0].reason.as_deref().unwrap().contains(&sha[..12]));
    let last = entries.last().unwrap();
    assert_eq!(last.action, "accept_proposal");
    assert_eq!(last.object_id, format!("{sha}:finding:{fid}"));
    assert_eq!(last.after.as_ref().unwrap()["imported_from"], "analyst:ann");
    assert_eq!(status_of(&b, &fid), "confirmed");
    // B's state is now B's own analyst decision, with A's reason as the disposition
    assert_eq!(
        text(
            &b,
            &format!("SELECT disposition_reason FROM findings WHERE finding_id = '{fid}'")
        ),
        "AiTM relay"
    );
    assert_eq!(
        text(
            &b,
            &format!(
                "SELECT CAST(review_state AS VARCHAR) || ' ' || reviewed_by FROM findings WHERE finding_id = '{fid}'"
            )
        ),
        "accepted analyst:bob"
    );
    assert!(share::proposals(b.conn()).unwrap().is_empty());
    assert_eq!(
        text(
            &b,
            "SELECT state || ' ' || decided_by FROM imported_proposals"
        ),
        "accepted analyst:bob"
    );
    // accepting again is refused
    let e = share::accept(b.conn(), &bob, &sha, &format!("finding:{fid}")).unwrap_err();
    assert!(matches!(e, Error::Decision(_)), "{e}");
    assert!(audit::verify(b.conn()).unwrap().ok);
}

#[test]
fn accepting_indicators_entries_and_notes_reaches_a_state() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let ev = first_evidence(&a);
    let fid = first_finding(&a);
    add_indicator(
        a.conn(),
        &ann.as_actor(),
        None,
        IndicatorType::Ip,
        "203.0.113.7",
        Verdict::Malicious,
        Some("relay"),
    )
    .unwrap();
    let gone = add_indicator(
        a.conn(),
        &ann.as_actor(),
        Some("t1"),
        IndicatorType::Upn,
        "user@example.test",
        Verdict::Suspicious,
        None,
    )
    .unwrap();
    remove_indicator(a.conn(), &ann.as_actor(), &gone).unwrap();
    let (eid, _) = te::propose(
        a.conn(),
        &ann.as_actor(),
        NewEntry {
            tenant_key: None,
            event_time: chrono::DateTime::from_timestamp(1_785_000_000, 0).unwrap(),
            title: "Sign-in from relay".into(),
            narrative: None,
            phase: Phase::InitialAccess,
            evidence: vec![te::EvidenceRef::parse(&ev).unwrap()],
        },
    )
    .unwrap();
    te::verify(a.conn(), &ann.as_actor(), &eid).unwrap();
    add_note(
        a.conn(),
        &ann.as_actor(),
        NoteTarget::Finding(fid.clone()),
        "seen by ann",
    )
    .unwrap();
    let bundle = share::export(a.conn(), &ann).unwrap();
    assert_eq!(bundle.items.len(), 4);
    let (bytes, sha) = share::to_bytes(&bundle).unwrap();
    let s = share::import(b.conn(), &bob, &bytes).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts, s.missing), (4, 0, 0, 0));
    for p in share::proposals(b.conn()).unwrap() {
        share::accept(b.conn(), &bob, &sha, &p.item_key).unwrap();
    }
    assert!(share::proposals(b.conn()).unwrap().is_empty());
    // B now holds the same work, as bob's decisions (the entry under a new id: entry ids are B's own)
    let mine = share::export(b.conn(), &bob).unwrap();
    let strip = |items: &[Item]| -> Vec<Item> {
        items
            .iter()
            .map(|i| match i {
                Item::TimelineEntry { .. } => {
                    let mut i = i.clone();
                    if let Item::TimelineEntry {
                        entry_id,
                        supersedes,
                        ..
                    } = &mut i
                    {
                        entry_id.clear();
                        supersedes.clear();
                    }
                    i
                }
                other => other.clone(),
            })
            .collect()
    };
    assert_eq!(strip(&mine.items), strip(&bundle.items));
    assert_eq!(
        count(
            &b,
            "SELECT count(*) FROM case_indicators WHERE decided_by = 'analyst:bob' AND CAST(review_state AS VARCHAR) = 'accepted'"
        ),
        2
    );
    assert_eq!(
        count(
            &b,
            "SELECT count(*) FROM annotations WHERE actor = 'analyst:bob' AND text = 'seen by ann'"
        ),
        1
    );
    assert!(audit::verify(b.conn()).unwrap().ok);
}

#[test]
fn evidence_mismatch_is_refused_and_stores_nothing() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let mut bundle = share::export(a.conn(), &ann).unwrap();
    bundle.evidence.source_files.push("00".repeat(32));
    bundle.evidence.source_files.sort();
    let (bytes, _) = share::to_bytes(&bundle).unwrap();
    let audit_before = count(&b, "SELECT count(*) FROM audit_trail");
    let e = share::import(b.conn(), &Reviewer::analyst("bob").unwrap(), &bytes).unwrap_err();
    assert!(
        matches!(&e, Error::Invalid(m) if m.contains("evidence") && m.contains("1 files only in the bundle, 0 only here")),
        "{e}"
    );
    assert_eq!(count(&b, "SELECT count(*) FROM imported_proposals"), 0);
    assert_eq!(count(&b, "SELECT count(*) FROM audit_trail"), audit_before);
}

#[test]
fn rule_set_difference_is_a_warning() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let mut bundle = share::export(a.conn(), &ann).unwrap();
    let dropped = bundle.evidence.rules.remove(0);
    bundle.evidence.rules.push("SPW-ZZ-999:abc".into());
    let (bytes, _) = share::to_bytes(&bundle).unwrap();
    let s = share::import(b.conn(), &Reviewer::analyst("bob").unwrap(), &bytes).unwrap();
    assert_eq!(s.rules_only_in_bundle, vec!["SPW-ZZ-999:abc".to_string()]);
    assert_eq!(s.rules_only_here, vec![dropped]);
}

#[test]
fn classification_agrees_conflict_and_reimport_is_noop() {
    let (a, b) = two_copies();
    let (f1, f2) = two_findings(&a);
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &f1, S::Confirmed, Some("r")).unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &f2, S::Benign, Some("vendor")).unwrap();
    set_finding_status(b.conn(), &bob.as_actor(), &f1, S::Confirmed, Some("r")).unwrap();
    set_finding_status(b.conn(), &bob.as_actor(), &f2, S::Confirmed, Some("no")).unwrap();
    let (bytes, _) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &bytes).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts, s.missing), (0, 1, 1, 0));
    let open = share::proposals(b.conn()).unwrap();
    assert_eq!(open.len(), 1); // agrees is not open
    assert_eq!(open[0].classification, "conflict");
    assert_eq!(open[0].item_key, format!("finding:{f2}"));
    assert_eq!(
        open[0].current.as_ref().unwrap()["status"],
        "confirmed",
        "B's value at import"
    );
    let again = share::import(b.conn(), &bob, &bytes).unwrap();
    assert!(again.already_imported);
    assert_eq!((again.agrees, again.conflicts), (1, 1));
    assert_eq!(count(&b, "SELECT count(*) FROM imported_proposals"), 2);
    assert_eq!(
        count(
            &b,
            "SELECT count(*) FROM audit_trail WHERE action = 'import_share'"
        ),
        1
    );
}

#[test]
fn newer_bundle_supersedes_open_proposals() {
    let (a, b) = two_copies();
    let fid = first_finding(&a);
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &fid, S::Confirmed, Some("r1")).unwrap();
    let (b1, sha1) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    share::import(b.conn(), &bob, &b1).unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &fid, S::Benign, Some("r2")).unwrap();
    let (b2, sha2) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    share::import(b.conn(), &bob, &b2).unwrap();
    let open = share::proposals(b.conn()).unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].bundle_sha256, sha2);
    assert_ne!(open[0].bundle_sha256, sha1);
    assert_eq!(
        text(
            &b,
            &format!("SELECT state FROM imported_proposals WHERE bundle_sha256 = '{sha1}'")
        ),
        "superseded"
    );
    // a superseded proposal cannot be accepted
    let e = share::accept(b.conn(), &bob, &sha1, &format!("finding:{fid}")).unwrap_err();
    assert!(matches!(e, Error::Decision(_)), "{e}");
}

#[test]
fn an_older_bundle_imported_later_does_not_supersede_a_newer_one() {
    let (a, b) = two_copies();
    let fid = first_finding(&a);
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &fid, S::Confirmed, Some("r1")).unwrap();
    let (old, sha_old) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &fid, S::Benign, Some("r2")).unwrap();
    let (new, sha_new) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    share::import(b.conn(), &bob, &new).unwrap();
    share::import(b.conn(), &bob, &old).unwrap();
    let open = share::proposals(b.conn()).unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].bundle_sha256, sha_new);
    assert_eq!(
        text(
            &b,
            &format!("SELECT state FROM imported_proposals WHERE bundle_sha256 = '{sha_old}'")
        ),
        "superseded"
    );
}

#[test]
fn import_counts_missing_findings() {
    let (a, b) = two_copies();
    let fid = first_finding(&a);
    let ann = Reviewer::analyst("ann").unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &fid, S::Confirmed, Some("r")).unwrap();
    let mut bundle = share::export(a.conn(), &ann).unwrap();
    bundle.items.push(Item::Finding {
        finding_id: "ffffffffffffffff".into(),
        status: "benign".into(),
        disposition_reason: Some("x".into()),
    });
    bundle.items.push(Item::Note {
        target: "finding:ffffffffffffffff".into(),
        text: "on a finding B lacks".into(),
    });
    let (bytes, sha) = share::to_bytes(&bundle).unwrap();
    let s = share::import(b.conn(), &Reviewer::analyst("bob").unwrap(), &bytes).unwrap();
    assert_eq!((s.new, s.missing), (1, 2));
    assert_eq!(
        count(
            &b,
            "SELECT count(*) FROM findings WHERE finding_id = 'ffffffffffffffff'"
        ),
        0
    );
    let e = share::accept(
        b.conn(),
        &Reviewer::analyst("bob").unwrap(),
        &sha,
        "finding:ffffffffffffffff",
    )
    .unwrap_err();
    assert!(matches!(e, Error::Decision(_)));
    // a missing proposal can still be discarded
    share::discard(
        b.conn(),
        &Reviewer::analyst("bob").unwrap(),
        &sha,
        "finding:ffffffffffffffff",
        None,
    )
    .unwrap();
}

#[test]
fn accept_refused_when_object_changed_since_import_and_discard_is_audited() {
    let (a, b) = two_copies();
    let fid = first_finding(&a);
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &fid, S::Confirmed, Some("r")).unwrap();
    let (bytes, sha) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    share::import(b.conn(), &bob, &bytes).unwrap();
    set_finding_status(b.conn(), &bob.as_actor(), &fid, S::NeedsMoreData, None).unwrap();
    let key = format!("finding:{fid}");
    let e = share::accept(b.conn(), &bob, &sha, &key).unwrap_err();
    assert!(
        matches!(&e, Error::Decision(m) if m.contains("changed since")),
        "{e}"
    );
    assert_eq!(status_of(&b, &fid), "needs_more_data");
    let d = share::discard(b.conn(), &bob, &sha, &key, Some("keep mine")).unwrap();
    assert_eq!(d.action, "discard_proposal");
    assert_eq!(d.actor, "analyst:bob");
    assert_eq!(d.object_type, "share_bundle");
    assert_eq!(d.object_id, format!("{sha}:{key}"));
    assert_eq!(d.reason.as_deref(), Some("keep mine"));
    assert_eq!(d.after.as_ref().unwrap()["state"], "discarded");
    assert!(share::proposals(b.conn()).unwrap().is_empty());
    let e = share::discard(b.conn(), &bob, &sha, &key, None).unwrap_err();
    assert!(matches!(e, Error::Decision(_)), "{e}");
    let e = share::discard(b.conn(), &bob, &sha, "finding:nope", None).unwrap_err();
    assert!(matches!(e, Error::NotFound(_)), "{e}");
}

#[test]
fn accept_respects_a_pending_agent_decision() {
    let (a, b) = two_copies();
    let fid = first_finding(&a);
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let agent = Actor::agent("claude", Some("bob")).unwrap();
    set_finding_status(b.conn(), &agent, &fid, S::InReview, None).unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &fid, S::Confirmed, Some("r")).unwrap();
    let (bytes, sha) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &bytes).unwrap();
    assert_eq!(s.conflicts, 1);
    let e = share::accept(b.conn(), &bob, &sha, &format!("finding:{fid}")).unwrap_err();
    assert!(
        matches!(&e, Error::Decision(m) if m.contains("pending")),
        "{e}"
    );
    assert_eq!(status_of(&b, &fid), "in_review");
    assert_eq!(share::proposals(b.conn()).unwrap().len(), 1, "stays open");
}

#[test]
fn parse_refuses_oversize_and_wrong_format() {
    assert!(share::parse(&vec![b' '; share::MAX_BUNDLE_BYTES + 1]).is_err());
    let s = br#"{"format":2,"exported_at":"x","analyst":"analyst:a","source_case_id":"c","source_audit_head":{"seq":0,"hash":null},"evidence":{"source_files":[],"rules":[]},"items":[]}"#;
    assert!(matches!(share::parse(s).unwrap_err(), Error::Invalid(_)));
}

#[test]
fn parse_refuses_bad_values() {
    let bundle = |analyst: &str, items: &str| {
        format!(
            r#"{{"format":1,"exported_at":"2026-10-07T00:00:00.000000Z","analyst":"{analyst}","source_case_id":"c","source_audit_head":{{"seq":0,"hash":null}},"evidence":{{"source_files":[],"rules":[]}},"items":[{items}]}}"#
        )
    };
    let ok = bundle(
        "analyst:a",
        r#"{"kind":"finding","finding_id":"f","status":"benign","disposition_reason":"r"}"#,
    );
    let (b, sha) = share::parse(ok.as_bytes()).unwrap();
    assert_eq!(b.items.len(), 1);
    assert_eq!(sha.len(), 64);
    for (analyst, items) in [
        ("agent:x", ""),
        ("analyst:", ""),
        (
            "analyst:a",
            r#"{"kind":"finding","finding_id":"f","status":"bogus","disposition_reason":null}"#,
        ),
        (
            "analyst:a",
            r#"{"kind":"indicator","tenant_key":null,"ioc_type":"ip","value":"1.2.3.4","verdict":"evil","note":null,"active":true}"#,
        ),
        (
            "analyst:a",
            r#"{"kind":"indicator","tenant_key":null,"ioc_type":"ip","value":" ","verdict":"benign","note":null,"active":true}"#,
        ),
        (
            "analyst:a",
            r#"{"kind":"timeline_entry","entry_id":"e","tenant_key":null,"event_time":"yesterday","title":"t","narrative":null,"phase":"recon","status":"verified","evidence":["signins:k"],"supersedes":[]}"#,
        ),
        (
            "analyst:a",
            r#"{"kind":"timeline_entry","entry_id":"e","tenant_key":null,"event_time":"2026-10-07T00:00:00.000000Z","title":"t","narrative":null,"phase":"recon","status":"proposed","evidence":["signins:k"],"supersedes":[]}"#,
        ),
        (
            "analyst:a",
            r#"{"kind":"timeline_entry","entry_id":"e","tenant_key":null,"event_time":"2026-10-07T00:00:00.000000Z","title":"t","narrative":null,"phase":"recon","status":"verified","evidence":[],"supersedes":[]}"#,
        ),
        (
            "analyst:a",
            r#"{"kind":"note","target":"nocolon","text":"t"}"#,
        ),
        (
            "analyst:a",
            r#"{"kind":"note","target":"finding:f","text":" "}"#,
        ),
        // the same key twice
        (
            "analyst:a",
            r#"{"kind":"note","target":"finding:f","text":"t"},{"kind":"note","target":"finding:f","text":"t"}"#,
        ),
    ] {
        let e = share::parse(bundle(analyst, items).as_bytes()).unwrap_err();
        assert!(matches!(e, Error::Invalid(_)), "{analyst} {items}: {e}");
    }
    let long = bundle(
        "analyst:a",
        &format!(
            r#"{{"kind":"note","target":"finding:f","text":"{}"}}"#,
            "a".repeat(17 * 1024)
        ),
    );
    assert!(matches!(
        share::parse(long.as_bytes()).unwrap_err(),
        Error::Invalid(_)
    ));
}

// ---------------------------------------------------------------- rulings on Task 3

fn entries_here(c: &Case) -> Vec<(String, String, String)> {
    let mut stmt = c
        .conn()
        .prepare("SELECT entry_id, CAST(status AS VARCHAR), title FROM timeline_entries ORDER BY created_at, entry_id")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn an_accepted_entry_is_matched_in_later_bundles() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let ev = first_evidence(&a);
    let (e1, _) = te::propose(
        a.conn(),
        &ann.as_actor(),
        NewEntry {
            tenant_key: None,
            event_time: chrono::DateTime::from_timestamp(1_785_000_000, 0).unwrap(),
            title: "Sign-in from relay".into(),
            narrative: None,
            phase: Phase::InitialAccess,
            evidence: vec![te::EvidenceRef::parse(&ev).unwrap()],
        },
    )
    .unwrap();
    te::verify(a.conn(), &ann.as_actor(), &e1).unwrap();
    // bundle 1: new; accepting it makes B's own entry and records its id
    let (b1, sha1) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &b1).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts), (1, 0, 0));
    share::accept(b.conn(), &bob, &sha1, &format!("timeline_entry:{e1}")).unwrap();
    let here = entries_here(&b);
    assert_eq!(here.len(), 1);
    let b_entry = here[0].0.clone();
    assert_ne!(b_entry, e1, "entry ids are per case");
    assert_eq!(
        text(
            &b,
            &format!(
                "SELECT applied_entry_id FROM imported_proposals WHERE bundle_sha256 = '{sha1}'"
            )
        ),
        b_entry
    );
    // bundle 2, A unchanged: agrees with the applied entry
    let (b2, _) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &b2).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts), (0, 1, 0));
    // A edits the title: A's successor names e1 in its lineage
    let (e2, _) = te::edit(
        a.conn(),
        &ann.as_actor(),
        &e1,
        te::EntryEdit {
            title: Some("Sign-in from the relay host".into()),
            ..te::EntryEdit::default()
        },
    )
    .unwrap();
    te::verify(a.conn(), &ann.as_actor(), &e2).unwrap();
    let bundle3 = share::export(a.conn(), &ann).unwrap();
    assert!(bundle3.items.iter().any(|i| matches!(i,
        Item::TimelineEntry { entry_id, supersedes, .. } if entry_id == &e2 && supersedes == &vec![e1.clone()])));
    let (b3, sha3) = share::to_bytes(&bundle3).unwrap();
    let s = share::import(b.conn(), &bob, &b3).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts), (0, 0, 1));
    let p = share::proposals(b.conn()).unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(
        p[0].current.as_ref().unwrap()["title"],
        "Sign-in from relay"
    );
    // accepting edits B's applied entry (a successor of it), no second independent entry
    share::accept(b.conn(), &bob, &sha3, &format!("timeline_entry:{e2}")).unwrap();
    let here = entries_here(&b);
    assert_eq!(here.len(), 2, "{here:?}");
    assert_eq!(
        (here[0].0.as_str(), here[0].1.as_str()),
        (b_entry.as_str(), "superseded")
    );
    assert_eq!(
        (here[1].1.as_str(), here[1].2.as_str()),
        ("verified", "Sign-in from the relay host")
    );
    assert_eq!(
        text(
            &b,
            &format!(
                "SELECT supersedes FROM timeline_entries WHERE entry_id = '{}'",
                here[1].0
            )
        ),
        b_entry
    );
    assert_eq!(
        text(
            &b,
            &format!(
                "SELECT applied_entry_id FROM imported_proposals WHERE bundle_sha256 = '{sha3}'"
            )
        ),
        here[1].0
    );
    // and a further bundle agrees again
    let (b4, _) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &b4).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts), (0, 1, 0));
    assert!(audit::verify(b.conn()).unwrap().ok);
}

#[test]
fn an_open_entry_proposal_is_superseded_by_its_edited_successor() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let ev = first_evidence(&a);
    let (e1, _) = te::propose(
        a.conn(),
        &ann.as_actor(),
        NewEntry {
            tenant_key: None,
            event_time: chrono::DateTime::from_timestamp(1_785_000_000, 0).unwrap(),
            title: "First".into(),
            narrative: None,
            phase: Phase::Recon,
            evidence: vec![te::EvidenceRef::parse(&ev).unwrap()],
        },
    )
    .unwrap();
    te::verify(a.conn(), &ann.as_actor(), &e1).unwrap();
    let (b1, sha1) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    share::import(b.conn(), &bob, &b1).unwrap();
    let (e2, _) = te::edit(
        a.conn(),
        &ann.as_actor(),
        &e1,
        te::EntryEdit {
            title: Some("Second".into()),
            ..te::EntryEdit::default()
        },
    )
    .unwrap();
    te::verify(a.conn(), &ann.as_actor(), &e2).unwrap();
    let (b2, sha2) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    share::import(b.conn(), &bob, &b2).unwrap();
    let open = share::proposals(b.conn()).unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(
        (open[0].bundle_sha256.as_str(), open[0].item_key.clone()),
        (sha2.as_str(), format!("timeline_entry:{e2}"))
    );
    assert_eq!(
        text(
            &b,
            &format!("SELECT state FROM imported_proposals WHERE bundle_sha256 = '{sha1}'")
        ),
        "superseded"
    );
}

#[test]
fn an_indicator_value_differing_only_in_case_agrees() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    add_indicator(
        a.conn(),
        &ann.as_actor(),
        None,
        IndicatorType::Upn,
        "User@Example.TEST",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    add_indicator(
        b.conn(),
        &bob.as_actor(),
        None,
        IndicatorType::Upn,
        "user@example.test",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    let (bytes, _) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &bytes).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts), (0, 1, 0));
    // a different verdict on the same value is still a conflict
    let (c, _) = two_copies();
    add_indicator(
        c.conn(),
        &bob.as_actor(),
        None,
        IndicatorType::Upn,
        "user@example.test",
        Verdict::Benign,
        None,
    )
    .unwrap();
    let s = share::import(c.conn(), &bob, &bytes).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts), (0, 0, 1));
}

// ---------------------------------------------------------------- review fixes on Task 3

fn verified_entry(c: &Case, who: &Reviewer, title: &str) -> String {
    let ev = first_evidence(c);
    let (id, _) = te::propose(
        c.conn(),
        &who.as_actor(),
        NewEntry {
            tenant_key: None,
            event_time: chrono::DateTime::from_timestamp(1_785_000_000, 0).unwrap(),
            title: title.into(),
            narrative: None,
            phase: Phase::Persistence,
            evidence: vec![te::EvidenceRef::parse(&ev).unwrap()],
        },
    )
    .unwrap();
    te::verify(c.conn(), &who.as_actor(), &id).unwrap();
    id
}

#[test]
fn a_note_on_an_imported_entry_waits_for_the_entry_then_lands_on_b_entry() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let e1 = verified_entry(&a, &ann, "Inbox rule");
    add_note(
        a.conn(),
        &ann.as_actor(),
        NoteTarget::Entry(e1.clone()),
        "hides replies",
    )
    .unwrap();
    let (bytes, sha) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &bytes).unwrap();
    assert_eq!(
        (s.new, s.missing),
        (2, 0),
        "the note depends on the entry, it is not missing"
    );
    let note_key = share::proposals(b.conn())
        .unwrap()
        .into_iter()
        .find(|p| p.item_key.starts_with("note:"))
        .unwrap()
        .item_key;
    // before its entry: refused, still open
    let e = share::accept(b.conn(), &bob, &sha, &note_key).unwrap_err();
    assert!(
        matches!(&e, Error::Decision(m) if m.contains("accept the proposal of its timeline entry")),
        "{e}"
    );
    assert_eq!(share::proposals(b.conn()).unwrap().len(), 2);
    // entry, then note: the note is on B's entry
    share::accept(b.conn(), &bob, &sha, &format!("timeline_entry:{e1}")).unwrap();
    let b_entry = text(&b, "SELECT entry_id FROM timeline_entries");
    assert_ne!(b_entry, e1);
    share::accept(b.conn(), &bob, &sha, &note_key).unwrap();
    assert_eq!(
        text(
            &b,
            "SELECT CAST(object_type AS VARCHAR) || ':' || object_id || ' ' || text || ' ' || actor FROM annotations"
        ),
        format!("timeline_entry:{b_entry} hides replies analyst:bob")
    );
    // a later bundle's note on the same entry agrees
    let (b2, _) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &b2).unwrap();
    assert_eq!((s.new, s.agrees, s.conflicts, s.missing), (0, 2, 0, 0));
}

#[test]
fn accepting_a_rejected_version_reconciles_the_content_then_rejects() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let e1 = verified_entry(&a, &ann, "Inbox rule");
    let (b1, sha1) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    share::import(b.conn(), &bob, &b1).unwrap();
    share::accept(b.conn(), &bob, &sha1, &format!("timeline_entry:{e1}")).unwrap();
    // A edits the title, verifies the edit, then rejects it: A's resulting state is the rejected new version
    let (e2, _) = te::edit(
        a.conn(),
        &ann.as_actor(),
        &e1,
        te::EntryEdit {
            title: Some("Inbox rule (not the attacker)".into()),
            ..te::EntryEdit::default()
        },
    )
    .unwrap();
    te::verify(a.conn(), &ann.as_actor(), &e2).unwrap();
    te::reject(a.conn(), &ann.as_actor(), &e2, "a helpdesk rule").unwrap();
    let bundle = share::export(a.conn(), &ann).unwrap();
    let item = bundle
        .items
        .iter()
        .find(|i| matches!(i, Item::TimelineEntry { .. }))
        .unwrap()
        .clone();
    assert!(
        matches!(&item, Item::TimelineEntry { status, supersedes, .. } if status == "rejected" && supersedes == &vec![e1.clone()])
    );
    let (b2, sha2) = share::to_bytes(&bundle).unwrap();
    let s = share::import(b.conn(), &bob, &b2).unwrap();
    assert_eq!(s.conflicts, 1);
    share::accept(b.conn(), &bob, &sha2, &format!("timeline_entry:{e2}")).unwrap();
    // B now ends as A: the old content superseded, the new content rejected
    let here = entries_here(&b);
    assert_eq!(here.len(), 2, "{here:?}");
    assert_eq!(here[0].1, "superseded");
    assert_eq!(
        (here[1].1.as_str(), here[1].2.as_str()),
        ("rejected", "Inbox rule (not the attacker)")
    );
    let (b3, _) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let s = share::import(b.conn(), &bob, &b3).unwrap();
    assert_eq!(
        (s.new, s.agrees, s.conflicts),
        (0, 1, 0),
        "B's state equals the bundle item"
    );
}

#[test]
fn a_rejected_edit_proposal_does_not_replace_its_verified_original() {
    let (a, _b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let e1 = verified_entry(&a, &ann, "Inbox rule");
    let (e2, _) = te::edit(
        a.conn(),
        &ann.as_actor(),
        &e1,
        te::EntryEdit {
            title: Some("Changed".into()),
            ..te::EntryEdit::default()
        },
    )
    .unwrap();
    te::reject(a.conn(), &ann.as_actor(), &e2, "no").unwrap();
    let b = share::export(a.conn(), &ann).unwrap();
    let lineages: Vec<(String, Vec<String>)> = b
        .items
        .iter()
        .filter_map(|i| match i {
            Item::TimelineEntry {
                entry_id,
                supersedes,
                ..
            } => Some((entry_id.clone(), supersedes.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(lineages.len(), 2);
    assert!(lineages.contains(&(e1.clone(), vec![])));
    assert!(lineages.contains(&(e2.clone(), vec![])), "{lineages:?}");
}

#[test]
fn an_older_ancestor_imported_after_its_edited_successor_is_superseded() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let e1 = verified_entry(&a, &ann, "First");
    let (old, sha_old) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let (e2, _) = te::edit(
        a.conn(),
        &ann.as_actor(),
        &e1,
        te::EntryEdit {
            title: Some("Second".into()),
            ..te::EntryEdit::default()
        },
    )
    .unwrap();
    te::verify(a.conn(), &ann.as_actor(), &e2).unwrap();
    let (new, sha_new) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    share::import(b.conn(), &bob, &new).unwrap();
    share::import(b.conn(), &bob, &old).unwrap();
    let open = share::proposals(b.conn()).unwrap();
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(
        (open[0].bundle_sha256.as_str(), open[0].item_key.clone()),
        (sha_new.as_str(), format!("timeline_entry:{e2}"))
    );
    assert_eq!(
        text(
            &b,
            &format!("SELECT state FROM imported_proposals WHERE bundle_sha256 = '{sha_old}'")
        ),
        "superseded"
    );
}

#[test]
fn a_zero_item_bundle_reimport_is_a_noop() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let bundle = share::export(a.conn(), &ann).unwrap();
    assert!(bundle.items.is_empty());
    let (bytes, _) = share::to_bytes(&bundle).unwrap();
    let first = share::import(b.conn(), &bob, &bytes).unwrap();
    assert!(!first.already_imported);
    let again = share::import(b.conn(), &bob, &bytes).unwrap();
    assert!(again.already_imported);
    assert_eq!(
        count(
            &b,
            "SELECT count(*) FROM audit_trail WHERE action = 'import_share'"
        ),
        1
    );
}

#[test]
fn preview_matches_import_and_writes_nothing() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let bob = Reviewer::analyst("bob").unwrap();
    let (f1, f2) = two_findings(&a);
    set_finding_status(a.conn(), &ann.as_actor(), &f1, S::Confirmed, Some("r")).unwrap();
    set_finding_status(a.conn(), &ann.as_actor(), &f2, S::Benign, Some("vendor")).unwrap();
    set_finding_status(b.conn(), &bob.as_actor(), &f2, S::Confirmed, Some("no")).unwrap();
    let (bytes, _) = share::to_bytes(&share::export(a.conn(), &ann).unwrap()).unwrap();
    let audit_before = count(&b, "SELECT count(*) FROM audit_trail");
    let p = share::preview(b.conn(), &bytes).unwrap();
    assert_eq!(count(&b, "SELECT count(*) FROM imported_proposals"), 0);
    assert_eq!(count(&b, "SELECT count(*) FROM audit_trail"), audit_before);
    let i = share::import(b.conn(), &bob, &bytes).unwrap();
    assert!(p.new + p.agrees + p.conflicts + p.missing >= 2, "{p:?}");
    assert!(p.conflicts >= 1, "f2 differs between the copies: {p:?}");
    assert_eq!(p, i);
    assert!(!p.already_imported);
    let again = share::preview(b.conn(), &bytes).unwrap();
    assert!(again.already_imported);
    assert_eq!(
        (again.new, again.agrees, again.conflicts, again.missing),
        (i.new, i.agrees, i.conflicts, i.missing)
    );
}

#[test]
fn preview_refuses_other_evidence_like_import() {
    let (a, b) = two_copies();
    let ann = Reviewer::analyst("ann").unwrap();
    let mut bundle = share::export(a.conn(), &ann).unwrap();
    bundle.evidence.source_files.push("00".repeat(32));
    bundle.evidence.source_files.sort();
    let (bytes, _) = share::to_bytes(&bundle).unwrap();
    let audit_before = count(&b, "SELECT count(*) FROM audit_trail");
    let e = share::preview(b.conn(), &bytes).unwrap_err();
    assert!(
        matches!(&e, Error::Invalid(m) if m.contains("evidence") && m.contains("1 files only in the bundle, 0 only here")),
        "{e}"
    );
    assert_eq!(count(&b, "SELECT count(*) FROM imported_proposals"), 0);
    assert_eq!(count(&b, "SELECT count(*) FROM audit_trail"), audit_before);
}

#[test]
fn preview_refuses_a_malformed_bundle() {
    let (_a, b) = two_copies();
    assert!(share::preview(b.conn(), b"{}").is_err());
}
