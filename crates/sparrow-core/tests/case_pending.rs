use chrono::{TimeZone, Utc};
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::audit;
use sparrow_core::case::indicators::{IndicatorType, Verdict, add_indicator, remove_indicator};
use sparrow_core::case::review::{self, PendingDecision};
use sparrow_core::case::timeline_entries::{self as te, EntryEdit, EvidenceRef, NewEntry, Phase};
use sparrow_core::case::write::{FindingStatus as S, set_finding_status};
use sparrow_core::{Case, Error};

/// A finding (actor alice) and three sign-ins with provenance: k1 and k2 by alice, k3 by bob.
fn case() -> Case {
    let c = Case::in_memory().unwrap();
    c.conn()
        .execute_batch(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, actor_upn, created_by, created_at, updated_at)
             VALUES ('f1', 'fp1', 't1', 'SPW-ID-004', 1, 'x', 'high', 'AiTM sign-in', 'alice@contoso.example', 'rule', \
                     now(), now());
             INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('invictus', '/e/T1', 't', 't1');
             INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status)
                 VALUES (1, 'SignInLogs/signins.json', 100, 'aa', 'parsed');
             INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end,
                                         byte_offset, byte_length, raw_sha256) VALUES
                 ('signins', 'k1', 1, 0, 1, 1, 0, 50, 'r1'),
                 ('signins', 'k2', 1, 1, 2, 2, 50, 50, 'r2'),
                 ('signins', 'k3', 1, 2, 3, 3, 100, 50, 'r3');
             INSERT INTO signins (record_key, collection_id, event_time, user_upn, app_name) VALUES
                 ('k1', 1, TIMESTAMPTZ '2026-08-03 09:00:00+00', 'alice@contoso.example', 'Office'),
                 ('k2', 1, TIMESTAMPTZ '2026-08-03 09:05:00+00', 'alice@contoso.example', 'Office'),
                 ('k3', 1, TIMESTAMPTZ '2026-08-03 09:10:00+00', 'bob@contoso.example', 'Office');",
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

fn entry(title: &str, evidence: &[&str]) -> NewEntry {
    NewEntry {
        end_time: None,
        event_count: None,
        tenant_key: Some("t1".into()),
        event_time: Utc.with_ymd_and_hms(2026, 8, 3, 9, 0, 0).unwrap(),
        title: title.into(),
        narrative: None,
        phase: Phase::InitialAccess,
        evidence: evidence
            .iter()
            .map(|e| EvidenceRef::parse(e).unwrap())
            .collect(),
    }
}

fn find<'a>(items: &'a [PendingDecision], ty: &str, id: &str) -> &'a PendingDecision {
    items
        .iter()
        .find(|p| p.object_type == ty && p.object_id == id)
        .unwrap_or_else(|| panic!("no pending {ty} {id} in {items:?}"))
}

#[test]
fn pending_lists_every_pending_agent_decision_with_its_latest_audit_entry() {
    let c = case();
    let s = set_finding_status(c.conn(), &agent(), "f1", S::InReview, Some("looks real")).unwrap();
    let ind = add_indicator(
        c.conn(),
        &agent(),
        Some("t1"),
        IndicatorType::parse("upn").unwrap(),
        "mallory@contoso.example",
        Verdict::parse("malicious").unwrap(),
        None,
    )
    .unwrap();
    let ind_seq = review::latest_decision_seq(c.conn(), "indicator", &ind)
        .unwrap()
        .unwrap();
    let (one_user, p1) = te::propose(
        c.conn(),
        &agent(),
        entry("Alice signs in", &["signins:k1", "signins:k2"]),
    )
    .unwrap();
    let (two_users, p2) = te::propose(
        c.conn(),
        &agent(),
        entry("Two users", &["signins:k1", "signins:k3"]),
    )
    .unwrap();

    let items = review::pending(c.conn()).unwrap();
    assert_eq!(items.len(), 4, "{items:?}");
    // Oldest decision first.
    let seqs: Vec<i64> = items.iter().map(|p| p.decision_seq).collect();
    assert_eq!(seqs, vec![s.seq, ind_seq, p1.seq, p2.seq]);

    let f = find(&items, "finding", "f1");
    assert_eq!(f.decision_seq, s.seq);
    assert_eq!(f.action, "set_status");
    assert_eq!(f.actor, "agent:claude");
    assert_eq!(f.on_behalf_of.as_deref(), Some("analyst:carlos"));
    assert_eq!(f.decided_at, s.ts);
    assert_eq!(f.before, s.before);
    assert_eq!(f.after, s.after);
    assert_eq!(f.after.as_ref().unwrap()["status"], "in_review");
    assert_eq!(f.reason.as_deref(), Some("looks real"));
    assert_eq!(f.account.as_deref(), Some("alice@contoso.example"));
    assert_eq!(f.title, "AiTM sign-in");

    let i = find(&items, "indicator", &ind);
    assert_eq!(i.action, "add_ioc");
    assert_eq!(i.account.as_deref(), Some("mallory@contoso.example"));
    assert_eq!(i.title, "upn mallory@contoso.example");

    let e1 = find(&items, "timeline_entry", &one_user);
    assert_eq!(e1.action, "propose_entry");
    assert_eq!(e1.after, p1.after);
    assert_eq!(e1.account.as_deref(), Some("alice@contoso.example"));
    assert_eq!(e1.title, "Alice signs in");
    let e2 = find(&items, "timeline_entry", &two_users);
    assert_eq!(e2.account, None);

    // The JSON shape the app sends: decided_at as UTC RFC 3339 text.
    let v = serde_json::to_value(f).unwrap();
    assert_eq!(v["decided_at"], sparrow_core::case::audit::ts_text(&s.ts));
    assert_eq!(v["object_type"], "finding");

    // A reviewed decision leaves the queue.
    review::review_accept(c.conn(), &carlos(), "finding", "f1", s.seq, None).unwrap();
    let items = review::pending(c.conn()).unwrap();
    assert_eq!(items.len(), 3, "{items:?}");
    assert!(items.iter().all(|p| p.object_type != "finding"));

    // A new agent decision on the accepted finding puts it back, with the new seq.
    let again = set_finding_status(c.conn(), &agent(), "f1", S::Confirmed, Some("relay")).unwrap();
    let items = review::pending(c.conn()).unwrap();
    assert_eq!(items.len(), 4);
    assert_eq!(find(&items, "finding", "f1").decision_seq, again.seq);
    assert_eq!(items.last().unwrap().object_id, "f1");
}

#[test]
fn analyst_decisions_and_an_indicator_without_a_upn_have_no_account_or_no_place() {
    let c = case();
    // An analyst decision is accepted when made: never pending.
    set_finding_status(
        c.conn(),
        &carlos().as_actor(),
        "f1",
        S::Confirmed,
        Some("relay"),
    )
    .unwrap();
    te::propose(
        c.conn(),
        &carlos().as_actor(),
        entry("Mine", &["signins:k1"]),
    )
    .unwrap();
    assert!(review::pending(c.conn()).unwrap().is_empty());
    // An ip indicator is about no account.
    let ind = add_indicator(
        c.conn(),
        &agent(),
        None,
        IndicatorType::parse("ip").unwrap(),
        "203.0.113.9",
        Verdict::parse("suspicious").unwrap(),
        None,
    )
    .unwrap();
    let items = review::pending(c.conn()).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].object_id, ind);
    assert_eq!(items[0].account, None);
    assert_eq!(items[0].title, "ip 203.0.113.9");
}

#[test]
fn a_superseded_entry_never_appears() {
    let c = case();
    let (old, _) = te::propose(c.conn(), &agent(), entry("Sign-in", &["signins:k1"])).unwrap();
    te::verify(c.conn(), &agent(), &old).unwrap();
    let (new, _) = te::edit(
        c.conn(),
        &agent(),
        &old,
        EntryEdit {
            title: Some("Sign-in from the relay".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_ne!(new, old);
    te::verify(c.conn(), &agent(), &new).unwrap();
    let (status, state): (String, String) = c
        .conn()
        .query_row(
            "SELECT CAST(status AS VARCHAR), CAST(review_state AS VARCHAR) FROM timeline_entries WHERE entry_id = ?",
            [&old],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    // The old entry is still pending review, but superseded: the queue shows only its successor.
    assert_eq!(
        (status.as_str(), state.as_str()),
        ("superseded", "pending_review")
    );
    let items = review::pending(c.conn()).unwrap();
    let ids: Vec<&str> = items.iter().map(|p| p.object_id.as_str()).collect();
    assert_eq!(ids, vec![new.as_str()]);
    assert_eq!(items[0].action, "verify_entry");
}

#[test]
fn an_entry_backed_by_an_app_only_sign_in_has_no_account() {
    let c = case();
    c.conn()
        .execute_batch(
            "INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end,
                                         byte_offset, byte_length, raw_sha256)
                 VALUES ('signins', 'k4', 1, 3, 4, 4, 150, 50, 'r4');
             INSERT INTO signins (record_key, collection_id, event_time, user_upn, app_name)
                 VALUES ('k4', 1, TIMESTAMPTZ '2026-08-03 09:15:00+00', NULL, 'Office');",
        )
        .unwrap();
    let (app_only, _) =
        te::propose(c.conn(), &agent(), entry("App sign-in", &["signins:k4"])).unwrap();
    // An app-only row next to a user's row: not every row names that user.
    let (mixed, _) = te::propose(
        c.conn(),
        &agent(),
        entry("Alice and an app", &["signins:k1", "signins:k4"]),
    )
    .unwrap();
    let (alice, _) = te::propose(c.conn(), &agent(), entry("Alice", &["signins:k1"])).unwrap();
    let items = review::pending(c.conn()).unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(find(&items, "timeline_entry", &app_only).account, None);
    assert_eq!(find(&items, "timeline_entry", &mixed).account, None);
    assert_eq!(
        find(&items, "timeline_entry", &alice).account.as_deref(),
        Some("alice@contoso.example")
    );
}

#[test]
fn a_removed_indicator_and_a_legacy_decision_are_pending_too() {
    let c = case();
    let ind = add_indicator(
        c.conn(),
        &carlos().as_actor(),
        None,
        IndicatorType::parse("ip").unwrap(),
        "203.0.113.9",
        Verdict::parse("malicious").unwrap(),
        None,
    )
    .unwrap();
    assert!(remove_indicator(c.conn(), &agent(), &ind).unwrap());
    let removed_seq = review::latest_decision_seq(c.conn(), "indicator", &ind)
        .unwrap()
        .unwrap();
    // An indicator from before the audit trail, as the schema upgrade leaves it: pending, with one
    // `legacy_decision` entry by its original author.
    c.conn()
        .execute_batch(
            "INSERT INTO case_indicators (indicator_id, type, value, verdict, added_by, added_at, decided_by, \
             decided_at, review_state) VALUES ('legacy1', 'upn', 'mallory@contoso.example', 'suspicious', \
             'analyst:old', TIMESTAMPTZ '2026-01-01 00:00:00+00', 'analyst:old', TIMESTAMPTZ '2026-01-01 00:00:00+00', \
             'pending_review')",
        )
        .unwrap();
    let state = serde_json::json!({ "type": "upn", "value": "mallory@contoso.example", "verdict": "suspicious" });
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    let legacy = audit::append(
        c.conn(),
        "analyst:old",
        None,
        "legacy_decision",
        "indicator",
        "legacy1",
        None,
        Some(&state),
        None,
    )
    .unwrap();
    c.conn().execute_batch("COMMIT").unwrap();

    let items = review::pending(c.conn()).unwrap();
    assert_eq!(items.len(), 2, "{items:?}");
    let r = find(&items, "indicator", &ind);
    assert_eq!(
        (r.action.as_str(), r.decision_seq),
        ("remove_ioc", removed_seq)
    );
    let l = find(&items, "indicator", "legacy1");
    assert_eq!(
        (l.action.as_str(), l.decision_seq),
        ("legacy_decision", legacy.seq)
    );
    assert_eq!(l.actor, "analyst:old");
    assert_eq!(l.account.as_deref(), Some("mallory@contoso.example"));
}

#[test]
fn a_pending_object_without_a_decision_is_an_error() {
    let c = case();
    c.conn()
        .execute_batch(
            "UPDATE findings SET review_state = 'pending_review' WHERE finding_id = 'f1'",
        )
        .unwrap();
    let e = review::pending(c.conn()).unwrap_err();
    assert!(matches!(e, Error::Decision(_)), "{e:?}");
    assert!(e.to_string().contains("f1"), "{e}");
}

#[test]
fn every_tenants_pending_items_are_listed() {
    let c = case();
    c.conn()
        .execute_batch(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, actor_upn, created_by, created_at, updated_at)
             VALUES ('f2', 'fp2', 't2', 'SPW-ID-004', 1, 'x', 'high', 'AiTM sign-in', 'zoe@fabrikam.example', 'rule', \
                     now(), now());",
        )
        .unwrap();
    set_finding_status(c.conn(), &agent(), "f1", S::InReview, None).unwrap();
    set_finding_status(c.conn(), &agent(), "f2", S::InReview, None).unwrap();
    let items = review::pending(c.conn()).unwrap();
    let got: Vec<(&str, Option<&str>)> = items
        .iter()
        .map(|p| (p.object_id.as_str(), p.account.as_deref()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("f1", Some("alice@contoso.example")),
            ("f2", Some("zoe@fabrikam.example"))
        ]
    );
}
