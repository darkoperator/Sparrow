#[path = "common/synth.rs"]
mod synth;

use sparrow_core::Case;
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::indicators::{IndicatorType, Verdict, add_indicator, remove_indicator};
use sparrow_core::case::notes::{NoteTarget, add_note};
use sparrow_core::case::share::{self, Item};
use sparrow_core::case::timeline_entries::{self as te, NewEntry, Phase};
use sparrow_core::case::write::{FindingStatus as S, set_finding_status};
use sparrow_core::case::{audit, review};
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
