use chrono::{TimeZone, Utc};
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::indicators::{IndicatorType, Verdict, add_indicator, set_verdict};
use sparrow_core::case::notes::{NoteTarget, add_note};
use sparrow_core::case::timeline_entries::{self as te, EntryEdit, EvidenceRef, NewEntry, Phase};
use sparrow_core::case::write::{FindingStatus as S, set_finding_status};
use sparrow_core::case::{audit, review};
use sparrow_core::data::DataDirs;
use sparrow_core::export::report_md::{self, ReportOpts};
use sparrow_core::{Case, Error};

fn case_with_finding() -> Case {
    let c = Case::in_memory().unwrap();
    c.conn()
        .execute_batch(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, created_by, created_at, updated_at)
             VALUES ('f1', 'fp1', 't1', 'SPW-ID-004', 1, 'x', 'high', 'AiTM', 'rule', now(), now());",
        )
        .unwrap();
    c
}
fn agent() -> Actor {
    Actor::agent("claude", Some("carlos")).unwrap()
}
fn analyst() -> Actor {
    Actor::analyst("carlos").unwrap()
}
fn one(c: &Case, sql: &str) -> Option<String> {
    c.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// One evidence record (a `record_sources` row, as case_timeline builds them) to verify timeline entries against.
fn evidence(c: &Case) -> EvidenceRef {
    c.conn()
        .execute_batch(
            "INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('invictus', '/e/T1', 't', 't1');
             INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status)
                 VALUES (1, 'UAL/ual.json', 100, 'aa', 'parsed');
             INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end,
                                         byte_offset, byte_length, raw_sha256)
                 VALUES ('ual_events', 'k1', 1, 0, 1, 1, 0, 50, 'r1');",
        )
        .unwrap();
    EvidenceRef {
        source_table: "ual_events".into(),
        record_key: "k1".into(),
    }
}

fn entry(evidence: Vec<EvidenceRef>) -> NewEntry {
    NewEntry {
        tenant_key: None,
        event_time: Utc.with_ymd_and_hms(2026, 8, 1, 9, 0, 0).unwrap(),
        title: "Inbox rule created".into(),
        narrative: None,
        phase: Phase::parse("persistence").unwrap(),
        evidence,
    }
}

fn report(c: &Case, reviewed_only: bool) -> String {
    let mut out = Vec::new();
    report_md::write(
        c.conn(),
        &mut out,
        &ReportOpts {
            reviewed_only,
            generated_at: Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap(),
            dirs: DataDirs::default(),
        },
    )
    .unwrap();
    String::from_utf8(out).unwrap()
}

/// The object's review columns as text: (review_state, decided_by, reviewed_by, reviewed_at = decided_at).
fn review_cols(c: &Case, table: &str, key_col: &str, id: &str) -> (String, String, String, bool) {
    c.conn()
        .query_row(
            &format!(
                "SELECT CAST(review_state AS VARCHAR), decided_by, reviewed_by, reviewed_at = decided_at \
                 FROM {table} WHERE {key_col} = ?"
            ),
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

#[test]
fn analyst_actor_strings() {
    let a = analyst();
    assert_eq!(a.as_str(), "analyst:carlos");
    assert_eq!(a.on_behalf_of(), None);
    assert!(a.is_analyst());
    assert!(!agent().is_analyst());
    assert_eq!(Reviewer::analyst("carlos").unwrap().as_actor(), a);
    assert!(Actor::analyst("a:b").is_err());
    assert!(Actor::analyst(" ").is_err());
    assert!(Actor::analyst("a\u{7}b").is_err());
}

#[test]
fn analyst_finding_decision_is_accepted_when_made() {
    let c = case_with_finding();
    let e =
        set_finding_status(c.conn(), &analyst(), "f1", S::Confirmed, Some("hides mail")).unwrap();
    assert_eq!(e.actor, "analyst:carlos");
    assert_eq!(e.on_behalf_of, None);
    assert_eq!(e.after.as_ref().unwrap()["review_state"], "accepted");
    assert_eq!(
        one(&c, "SELECT CAST(review_state AS VARCHAR) FROM findings").as_deref(),
        Some("accepted")
    );
    assert_eq!(
        one(&c, "SELECT reviewed_by FROM findings").as_deref(),
        Some("analyst:carlos")
    );
    assert_eq!(
        one(
            &c,
            "SELECT CAST(reviewed_at = decided_at AS VARCHAR) FROM findings"
        )
        .as_deref(),
        Some("true")
    );
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn analyst_indicator_and_entry_decisions_are_accepted_when_made() {
    let c = case_with_finding();
    let ev = evidence(&c);
    // indicator: add, then change the verdict
    let id = add_indicator(
        c.conn(),
        &analyst(),
        None,
        IndicatorType::Ip,
        "203.0.113.9",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    let want = (
        "accepted".to_string(),
        "analyst:carlos".to_string(),
        "analyst:carlos".to_string(),
        true,
    );
    assert_eq!(
        review_cols(&c, "case_indicators", "indicator_id", &id),
        want
    );
    let e = set_verdict(c.conn(), &analyst(), &id, Verdict::Suspicious, None).unwrap();
    assert_eq!(e.after.as_ref().unwrap()["review_state"], "accepted");
    assert_eq!(
        review_cols(&c, "case_indicators", "indicator_id", &id),
        want
    );
    // timeline entry: propose, verify, then edit the verified entry (a successor)
    let (eid, p) = te::propose(c.conn(), &analyst(), entry(vec![ev])).unwrap();
    assert_eq!(p.after.as_ref().unwrap()["review_state"], "accepted");
    assert_eq!(review_cols(&c, "timeline_entries", "entry_id", &eid), want);
    let v = te::verify(c.conn(), &analyst(), &eid).unwrap();
    assert_eq!(v.after.as_ref().unwrap()["review_state"], "accepted");
    assert_eq!(review_cols(&c, "timeline_entries", "entry_id", &eid), want);
    let (succ, s) = te::edit(
        c.conn(),
        &analyst(),
        &eid,
        EntryEdit {
            title: Some("Inbox rule created by the attacker".into()),
            ..EntryEdit::default()
        },
    )
    .unwrap();
    assert_ne!(succ, eid);
    assert_eq!(s.after.as_ref().unwrap()["review_state"], "accepted");
    assert_eq!(review_cols(&c, "timeline_entries", "entry_id", &succ), want);
    te::verify(c.conn(), &analyst(), &succ).unwrap();
    assert_eq!(
        one(
            &c,
            &format!(
                "SELECT CAST(status AS VARCHAR) FROM timeline_entries WHERE entry_id = '{eid}'"
            )
        )
        .as_deref(),
        Some("superseded")
    );
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn analyst_write_refused_on_pending_agent_decision() {
    let pending = |e: &Error, seq: i64| matches!(e, Error::Decision(m) if m.contains("pending") && m.contains(&format!("audit seq {seq}")));
    // finding
    let c = case_with_finding();
    let ev = evidence(&c);
    let d = set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).unwrap();
    let e = set_finding_status(c.conn(), &analyst(), "f1", S::Benign, Some("x")).unwrap_err();
    assert!(pending(&e, d.seq), "{e}");
    // nothing was written: the agent decision is still the latest and still pending
    assert_eq!(
        review::latest_decision_seq(c.conn(), "finding", "f1").unwrap(),
        Some(d.seq)
    );
    assert_eq!(
        one(&c, "SELECT CAST(review_state AS VARCHAR) FROM findings").as_deref(),
        Some("pending_review")
    );
    // after the review the analyst may write
    review::review_accept(
        c.conn(),
        &Reviewer::analyst("carlos").unwrap(),
        "finding",
        "f1",
        d.seq,
        None,
    )
    .unwrap();
    set_finding_status(c.conn(), &analyst(), "f1", S::Benign, Some("x")).unwrap();
    // indicator: verdict change and re-add both refused
    let id = add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::Ip,
        "203.0.113.9",
        Verdict::Malicious,
        None,
    )
    .unwrap();
    let seq = review::latest_decision_seq(c.conn(), "indicator", &id)
        .unwrap()
        .unwrap();
    let e = set_verdict(c.conn(), &analyst(), &id, Verdict::Benign, None).unwrap_err();
    assert!(pending(&e, seq), "{e}");
    let e = add_indicator(
        c.conn(),
        &analyst(),
        None,
        IndicatorType::Ip,
        "203.0.113.9",
        Verdict::Benign,
        None,
    )
    .unwrap_err();
    assert!(pending(&e, seq), "{e}");
    // timeline entry: verify, reject and edit all refused
    let (eid, p) = te::propose(c.conn(), &agent(), entry(vec![ev])).unwrap();
    let e = te::verify(c.conn(), &analyst(), &eid).unwrap_err();
    assert!(pending(&e, p.seq), "{e}");
    let e = te::reject(c.conn(), &analyst(), &eid, "wrong").unwrap_err();
    assert!(pending(&e, p.seq), "{e}");
    let e = te::edit(
        c.conn(),
        &analyst(),
        &eid,
        EntryEdit {
            title: Some("Changed".into()),
            ..EntryEdit::default()
        },
    )
    .unwrap_err();
    assert!(pending(&e, p.seq), "{e}");
    // the agent itself is never refused
    te::verify(c.conn(), &agent(), &eid).unwrap();
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn agent_decision_after_analyst_one_is_pending_again() {
    let c = case_with_finding();
    set_finding_status(c.conn(), &analyst(), "f1", S::Confirmed, Some("r")).unwrap();
    set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).unwrap();
    assert_eq!(
        one(&c, "SELECT CAST(review_state AS VARCHAR) FROM findings").as_deref(),
        Some("pending_review")
    );
    assert_eq!(one(&c, "SELECT reviewed_by FROM findings"), None);
}

#[test]
fn analyst_note_is_labelled_and_kept_in_reviewed_only_report() {
    let c = case_with_finding();
    add_note(
        c.conn(),
        &analyst(),
        NoteTarget::Finding("f1".into()),
        "checked the rule",
    )
    .unwrap();
    add_note(
        c.conn(),
        &agent(),
        NoteTarget::Finding("f1".into()),
        "agent thought",
    )
    .unwrap();
    set_finding_status(c.conn(), &analyst(), "f1", S::Confirmed, Some("r")).unwrap();
    let md = report(&c, true);
    assert!(
        md.contains(&format!(
            "{} (analyst:carlos at ",
            sparrow_core::export::LABEL_ANALYST_NOTE
        )) && md.contains("checked the rule"),
        "{md}"
    );
    assert!(!md.contains("agent thought"), "{md}");
    assert!(!md.contains(report_md::LABEL_AGENT_NOTE), "{md}");
    assert!(md.contains("analyst decision by analyst:carlos"), "{md}");
    // the full report keeps both, each with its own label
    let md = report(&c, false);
    assert!(
        md.contains("checked the rule") && md.contains("agent thought"),
        "{md}"
    );
    assert!(
        md.contains(&format!(
            "{} (agent:claude on behalf of analyst:carlos at ",
            report_md::LABEL_AGENT_NOTE
        )),
        "{md}"
    );
}

#[test]
fn analyst_decision_class_needs_the_analyst_as_reviewer() {
    use sparrow_core::export::{DecisionClass, Provenance};
    let p = |decided: &str, reviewed: &str| Provenance {
        decided_by: Some(decided.into()),
        review_state: Some("accepted".into()),
        reviewed_by: Some(reviewed.into()),
        ..Provenance::default()
    };
    assert_eq!(
        p("analyst:carlos", "analyst:carlos").class(),
        DecisionClass::Analyst
    );
    // an agent decision accepted by an analyst stays "accepted"
    assert_eq!(
        p("agent:claude", "analyst:carlos").class(),
        DecisionClass::Accepted
    );
}
