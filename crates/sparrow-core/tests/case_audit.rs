use serde_json::json;
use sha2::Digest;
use sparrow_core::Case;
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::audit;
use sparrow_core::db::migrations::{MIGRATIONS, latest_version};

fn case() -> Case {
    Case::in_memory().unwrap()
}

fn append(c: &Case, n: usize) {
    let a = Actor::agent("t", Some("carlos")).unwrap();
    for i in 0..n {
        c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
        audit::append(
            c.conn(),
            a.as_str(),
            a.on_behalf_of(),
            "test",
            "finding",
            &format!("f{i}"),
            None,
            Some(&json!({"status": "in_review", "i": i})),
            None,
        )
        .unwrap();
        c.conn().execute_batch("COMMIT").unwrap();
    }
}

#[test]
fn empty_chain_verifies() {
    let r = audit::verify(case().conn()).unwrap();
    assert!(r.ok);
    assert_eq!(r.entries, 0);
    assert_eq!(r.head_hash, None);
}

#[test]
fn genesis_uses_the_case_id() {
    let c = case();
    append(&c, 1);
    let id = audit::case_id(c.conn()).unwrap();
    assert_eq!(uuid::Uuid::parse_str(&id).unwrap().to_string(), id);
    let want = hex::encode(sha2::Sha256::digest(format!("sparrow-audit-genesis{id}")));
    let e = &audit::log(c.conn(), None).unwrap()[0];
    assert_eq!(e.seq, 1);
    assert_eq!(e.prev_hash, want);
    assert_eq!(e.actor, "agent:t");
    assert_eq!(e.on_behalf_of.as_deref(), Some("analyst:carlos"));
    // Every case gets its own id, so two chains never share a genesis.
    assert_ne!(audit::case_id(case().conn()).unwrap(), id);
}

#[test]
fn chain_links_and_verifies() {
    let c = case();
    append(&c, 5);
    let log = audit::log(c.conn(), None).unwrap();
    assert_eq!(
        log.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    for w in log.windows(2) {
        assert_eq!(w[1].prev_hash, w[0].hash);
    }
    for e in &log {
        assert_eq!(audit::entry_hash(&e.prev_hash, e), e.hash);
    }
    let r = audit::verify(c.conn()).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.entries, 5);
    assert_eq!(r.head_hash.as_deref(), Some(log[4].hash.as_str()));
}

#[test]
fn log_filters_by_object() {
    let c = case();
    append(&c, 3);
    let one = audit::log(c.conn(), Some(("finding", "f1"))).unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!((one[0].seq, one[0].object_id.as_str()), (2, "f1"));
    assert!(
        audit::log(c.conn(), Some(("indicator", "f1")))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn canonical_json_sorts_keys_at_every_level() {
    let v = json!({"b": 1, "a": {"d": [{"z": 1, "y": 2}], "c": null}});
    assert_eq!(
        audit::canonical(&v),
        r#"{"a":{"c":null,"d":[{"y":2,"z":1}]},"b":1}"#
    );
}

#[test]
fn stored_json_round_trips_to_the_same_hash() {
    // Floats, big integers, nested objects and escapes must read back to the value that was hashed.
    let c = case();
    let a = Actor::agent("t", None).unwrap();
    let v = json!({"f": 0.1, "big": 9007199254740993_u64, "neg": -5, "e": 1e300, "s": "a\"b\\c/\u{1}",
                   "n": {"z": [1, 2.5, "x"], "a": true}});
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    audit::append(
        c.conn(),
        a.as_str(),
        None,
        "test",
        "finding",
        "f1",
        Some(&v),
        Some(&v),
        None,
    )
    .unwrap();
    c.conn().execute_batch("COMMIT").unwrap();
    let e = &audit::log(c.conn(), None).unwrap()[0];
    assert_eq!(e.before.as_ref(), Some(&v));
    assert_eq!(e.after.as_ref(), Some(&v));
    assert!(audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn tampered_row_is_reported_at_its_seq() {
    let c = case();
    append(&c, 4);
    c.conn()
        .execute(
            "UPDATE audit_trail SET after = '{\"status\":\"confirmed\"}' WHERE seq = 3",
            [],
        )
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(3));
    assert!(r.problem.unwrap().contains("hash"));
}

#[test]
fn tampered_timestamp_is_reported() {
    let c = case();
    append(&c, 2);
    c.conn()
        .execute(
            "UPDATE audit_trail SET ts = CAST('2020-01-01 00:00:00.000001+00' AS TIMESTAMPTZ) WHERE seq = 2",
            [],
        )
        .unwrap();
    assert_eq!(audit::verify(c.conn()).unwrap().first_bad_seq, Some(2));
}

#[test]
fn deleted_row_is_reported() {
    let c = case();
    append(&c, 4);
    c.conn()
        .execute("DELETE FROM audit_trail WHERE seq = 2", [])
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(2), "{r:?}"); // seq 2 missing: the dense sequence breaks at 2
}

#[test]
fn deleted_first_row_is_reported() {
    let c = case();
    append(&c, 3);
    c.conn()
        .execute("DELETE FROM audit_trail WHERE seq = 1", [])
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert_eq!(r.first_bad_seq, Some(1), "{r:?}");
}

#[test]
fn reordered_rows_are_reported() {
    let c = case();
    append(&c, 3);
    c.conn().execute_batch(
        "UPDATE audit_trail SET seq = 100 WHERE seq = 2; UPDATE audit_trail SET seq = 2 WHERE seq = 3; UPDATE audit_trail SET seq = 3 WHERE seq = 100;",
    ).unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(2), "{r:?}");
}

#[test]
fn a_rehashed_row_still_breaks_the_link_to_the_next_one() {
    // An attacker who edits a row and recomputes its hash breaks the next row's prev_hash.
    let c = case();
    append(&c, 3);
    let mut e = audit::log(c.conn(), None).unwrap()[1].clone();
    e.reason = Some("forged".into());
    let forged = audit::entry_hash(&e.prev_hash, &e);
    c.conn()
        .execute(
            "UPDATE audit_trail SET reason = 'forged', hash = ? WHERE seq = 2",
            [forged],
        )
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert_eq!(r.first_bad_seq, Some(3), "{r:?}");
    assert!(r.problem.unwrap().contains("prev_hash"));
}

#[test]
fn hash_is_stable_for_unicode_and_control_text() {
    let c = case();
    let a = Actor::agent("t", None).unwrap();
    let text = "Ünïcødé 🔥 \u{202E}rtl\u{0000}nul\nline\t\"q\"";
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    audit::append(
        c.conn(),
        a.as_str(),
        None,
        "note",
        "finding",
        "f1",
        None,
        Some(&json!({"text": text})),
        Some(text),
    )
    .unwrap();
    c.conn().execute_batch("COMMIT").unwrap();
    assert!(audit::verify(c.conn()).unwrap().ok);
    let e = &audit::log(c.conn(), None).unwrap()[0];
    assert_eq!(e.reason.as_deref(), Some(text));
    assert_eq!(e.after.as_ref().unwrap()["text"], text);
}

#[test]
fn append_refuses_on_a_broken_chain_until_acknowledged() {
    let c = case();
    append(&c, 2);
    c.conn()
        .execute("UPDATE audit_trail SET actor = 'x' WHERE seq = 1", [])
        .unwrap();
    let a = Actor::agent("t", None).unwrap();
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    let err = audit::append(
        c.conn(),
        a.as_str(),
        None,
        "test",
        "finding",
        "f9",
        None,
        None,
        None,
    )
    .unwrap_err();
    c.conn().execute_batch("ROLLBACK").unwrap();
    assert!(err.to_string().contains("audit chain is broken"), "{err}");
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 2);
    let ack = audit::acknowledge_break(c.conn(), &a).unwrap();
    assert_eq!(ack.action, "acknowledge_break");
    assert_eq!(ack.seq, 3);
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    audit::append(
        c.conn(),
        a.as_str(),
        None,
        "test",
        "finding",
        "f9",
        None,
        None,
        None,
    )
    .unwrap();
    c.conn().execute_batch("COMMIT").unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.entries, 4);
    assert_eq!(r.acknowledged_breaks, vec![1]);
}

#[test]
fn acknowledging_an_intact_chain_is_refused() {
    let c = case();
    append(&c, 1);
    let a = Actor::agent("t", None).unwrap();
    assert!(audit::acknowledge_break(c.conn(), &a).is_err());
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 1);
}

#[test]
fn a_new_break_after_an_acknowledgement_is_reported() {
    let c = case();
    append(&c, 2);
    c.conn()
        .execute("UPDATE audit_trail SET actor = 'x' WHERE seq = 1", [])
        .unwrap();
    let a = Actor::agent("t", None).unwrap();
    audit::acknowledge_break(c.conn(), &a).unwrap();
    append(&c, 2);
    c.conn()
        .execute("UPDATE audit_trail SET actor = 'y' WHERE seq = 5", [])
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(5));
    assert_eq!(r.acknowledged_breaks, vec![1]);
}

#[test]
fn actor_validates_ids() {
    assert!(Actor::agent("", None).is_err());
    assert!(Actor::agent("   ", None).is_err());
    assert!(Actor::agent("a\u{7}b", None).is_err());
    assert!(Actor::agent("a:b", None).is_err());
    assert!(Actor::agent("claude", Some("")).is_err());
    assert!(Actor::agent("claude", Some("x\ny")).is_err());
    let a = Actor::agent("claude", Some("carlos")).unwrap();
    assert_eq!(a.as_str(), "agent:claude");
    assert_eq!(a.on_behalf_of(), Some("analyst:carlos"));
    assert_eq!(Actor::agent(" claude ", None).unwrap().on_behalf_of(), None);
    assert_eq!(
        Actor::agent(" claude ", None).unwrap().as_str(),
        "agent:claude"
    );
    assert!(Reviewer::analyst("").is_err());
    assert_eq!(Reviewer::analyst("sam").unwrap().as_str(), "analyst:sam");
}

#[test]
fn second_writer_is_refused_and_chain_stays_linear() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("c.duckdb");
    let first = Case::create_or_open(&p).unwrap();
    append(&first, 1);
    let second = Case::create_or_open(&p);
    let err = second
        .err()
        .expect("DuckDB must refuse a second writer handle");
    assert!(matches!(err, sparrow_core::Error::WriterBusy(_)), "{err:?}");
    assert!(err.to_string().contains("another writer"), "{err}");
    assert!(
        Case::upgrade(&p)
            .unwrap_err()
            .to_string()
            .contains("another writer")
    );
    drop(first);
    let again = Case::create_or_open(&p).unwrap();
    append(&again, 1);
    let r = audit::verify(again.conn()).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.entries, 2);
}

/// A Phase 6 case: migrations 1-15 applied by hand, plus one indicator.
fn phase6_case(path: &std::path::Path) {
    let conn = duckdb::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL,
         applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
    )
    .unwrap();
    for m in MIGRATIONS.iter().filter(|m| m.version <= 15) {
        conn.execute_batch(m.sql).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
            duckdb::params![m.version as i64, m.name],
        )
        .unwrap();
    }
    conn.execute_batch(
        "INSERT INTO case_indicators (indicator_id, tenant_key, type, value, verdict, note, added_by, added_at) \
         VALUES ('0123456789abcdef', NULL, 'ip', '203.0.113.9', 'malicious', NULL, 'analyst:sam', \
                 TIMESTAMPTZ '2026-09-30 10:00:00+00')",
    )
    .unwrap();
}

#[test]
fn upgrading_a_phase6_case_starts_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p6.duckdb");
    phase6_case(&path);
    let (from, to) = Case::upgrade(&path).unwrap();
    assert_eq!((from, to), (15, latest_version()));
    assert!(to >= 16);
    let c = Case::open_read_only(&path).unwrap();
    assert!(!audit::case_id(c.conn()).unwrap().is_empty());
    let row: (String, String, String, i64) = c
        .conn()
        .query_row(
            "SELECT decided_by, CAST(review_state AS VARCHAR), added_by, \
                    epoch_us(decided_at) - epoch_us(added_at) FROM case_indicators",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        (
            "analyst:sam".into(),
            "pending_review".into(),
            "analyst:sam".into(),
            0
        )
    );
    let log = audit::log(c.conn(), None).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action, "schema_upgrade");
    assert_eq!(log[0].actor, "system:upgrade");
    assert_eq!(log[0].before.as_ref().unwrap()["schema_version"], 15);
    assert_eq!(log[0].after.as_ref().unwrap()["schema_version"], to as i64);
    assert!(audit::verify(c.conn()).unwrap().ok);
    drop(c);
    // Upgrading again changes nothing and appends nothing.
    assert_eq!(Case::upgrade(&path).unwrap(), (to, to));
    let c = Case::open_read_only(&path).unwrap();
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 1);
}

#[test]
fn a_fresh_case_has_an_empty_chain_and_no_decision_tags() {
    let c = case();
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), 0);
    let cols: Vec<String> = {
        let mut s = c
            .conn()
            .prepare(
                "SELECT column_name FROM duckdb_columns() WHERE table_name = 'findings' \
                 AND column_name IN ('decided_by','decided_at','on_behalf_of','review_state', \
                 'reviewed_by','reviewed_at','review_comment') ORDER BY column_name",
            )
            .unwrap();
        s.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(cols.len(), 7, "{cols:?}");
    for t in [
        "case_meta",
        "audit_trail",
        "timeline_entries",
        "timeline_entry_evidence",
        "annotations",
    ] {
        let n: i64 = c
            .conn()
            .query_row(
                "SELECT count(*) FROM duckdb_tables() WHERE table_name = ?",
                [t],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "{t}");
    }
}

/// A case with 3 entries whose seq 2 was tampered with and the break acknowledged (seq 4).
fn acknowledged_at_2() -> Case {
    let c = case();
    append(&c, 3);
    c.conn()
        .execute("UPDATE audit_trail SET reason = 'edited' WHERE seq = 2", [])
        .unwrap();
    let ack = audit::acknowledge_break(c.conn(), &Actor::agent("t", None).unwrap()).unwrap();
    assert_eq!(ack.seq, 4);
    let after = ack.after.unwrap();
    assert_eq!(after["first_bad_seq"], 2);
    assert!(after["problem"].as_str().unwrap().contains("hash"));
    assert!(after["acknowledged_hash"].is_string());
    assert!(after["acknowledged_content_hash"].is_string());
    let r = audit::verify(c.conn()).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.acknowledged_breaks, vec![2]);
    c
}

#[test]
fn an_acknowledgement_does_not_cover_a_later_tamper_elsewhere() {
    let c = acknowledged_at_2();
    c.conn()
        .execute("UPDATE audit_trail SET actor = 'x' WHERE seq = 1", [])
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(1), "{r:?}");
    // A tamper of a row between the acknowledged one and the acknowledgement is not covered either.
    let c = acknowledged_at_2();
    c.conn()
        .execute("UPDATE audit_trail SET actor = 'x' WHERE seq = 3", [])
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert_eq!(r.first_bad_seq, Some(3), "{r:?}");
}

#[test]
fn an_acknowledgement_does_not_cover_a_second_change_to_the_same_row() {
    let c = acknowledged_at_2();
    c.conn()
        .execute(
            "UPDATE audit_trail SET reason = 'edited again' WHERE seq = 2",
            [],
        )
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(2), "{r:?}");
    assert!(r.acknowledged_breaks.is_empty());
    // Changing the row's stored hash is caught too.
    let c = acknowledged_at_2();
    c.conn()
        .execute(
            "UPDATE audit_trail SET hash = 'ff' || hash WHERE seq = 2",
            [],
        )
        .unwrap();
    assert!(!audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn deleting_the_acknowledgement_reopens_the_break() {
    let c = acknowledged_at_2();
    c.conn()
        .execute("DELETE FROM audit_trail WHERE seq = 4", [])
        .unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(2), "{r:?}");
}

#[test]
fn several_breaks_need_one_acknowledgement_each() {
    let c = case();
    append(&c, 4);
    c.conn()
        .execute_batch(
            "UPDATE audit_trail SET reason = 'a' WHERE seq = 2; UPDATE audit_trail SET reason = 'b' WHERE seq = 3;",
        )
        .unwrap();
    let a = Actor::agent("t", None).unwrap();
    assert_eq!(
        audit::acknowledge_break(c.conn(), &a)
            .unwrap()
            .after
            .unwrap()["first_bad_seq"],
        2
    );
    let r = audit::verify(c.conn()).unwrap();
    assert_eq!((r.ok, r.first_bad_seq), (false, Some(3)), "{r:?}");
    audit::acknowledge_break(c.conn(), &a).unwrap();
    let r = audit::verify(c.conn()).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.acknowledged_breaks, vec![2, 3]);
}

#[cfg(unix)]
#[test]
fn a_symlink_to_an_open_case_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("c.duckdb");
    let link = dir.path().join("alias.duckdb");
    let first = Case::create_or_open(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = Case::create_or_open(&link)
        .err()
        .expect("an alias is the same file");
    assert!(matches!(err, sparrow_core::Error::WriterBusy(_)), "{err:?}");
    // A path through `..` is the same file too.
    let dotted = dir.path().join("sub").join("..").join("c.duckdb");
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    assert!(Case::create_or_open(&dotted).is_err());
    drop(first);
    let via_link = Case::create_or_open(&link).unwrap();
    assert!(Case::create_or_open(&real).is_err());
    drop(via_link);
}

/// Appending one more entry fails with ChainBroken, and writes nothing.
fn append_is_refused(c: &Case) {
    let n = audit::log(c.conn(), None).unwrap().len();
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    let err = audit::append(
        c.conn(),
        "agent:t",
        None,
        "test",
        "finding",
        "fz",
        None,
        None,
        None,
    )
    .unwrap_err();
    c.conn().execute_batch("ROLLBACK").unwrap();
    assert!(
        matches!(err, sparrow_core::Error::ChainBroken(_)),
        "{err:?}"
    );
    assert_eq!(audit::log(c.conn(), None).unwrap().len(), n);
}

#[test]
fn every_tamper_is_refused_on_the_append_path() {
    // Each case appends first, so the verified fingerprint is stored and the fast path is armed.
    let tampers: &[&str] = &[
        "UPDATE audit_trail SET after = '{\"status\":\"confirmed\"}' WHERE seq = 2",
        "UPDATE audit_trail SET reason = 'x' WHERE seq = 1",
        "UPDATE audit_trail SET on_behalf_of = NULL WHERE seq = 3",
        "UPDATE audit_trail SET ts = CAST('2020-01-01 00:00:00+00' AS TIMESTAMPTZ) WHERE seq = 2",
        "UPDATE audit_trail SET prev_hash = hash WHERE seq = 2",
        "DELETE FROM audit_trail WHERE seq = 2",
        "DELETE FROM audit_trail WHERE seq = 1",
        "UPDATE audit_trail SET seq = 100 WHERE seq = 2; UPDATE audit_trail SET seq = 2 WHERE seq = 3; \
         UPDATE audit_trail SET seq = 3 WHERE seq = 100;",
        "UPDATE case_meta SET value = 'another-case' WHERE key = 'case_id'",
    ];
    for sql in tampers {
        let c = case();
        append(&c, 3);
        c.conn().execute_batch(sql).unwrap();
        append_is_refused(&c);
    }
}

#[test]
fn a_tampered_head_is_refused_on_the_append_path() {
    // The head row is the one the stored fingerprint names: changing it must not pass as the verified head.
    let c = case();
    append(&c, 3);
    c.conn()
        .execute("UPDATE audit_trail SET actor = 'x' WHERE seq = 3", [])
        .unwrap();
    append_is_refused(&c);
}

#[test]
fn a_lost_fingerprint_falls_back_to_the_full_walk() {
    let c = case();
    append(&c, 2);
    c.conn()
        .execute("DELETE FROM case_meta WHERE key = 'audit_verified'", [])
        .unwrap();
    append(&c, 1);
    // A wrong stored fingerprint never hides a tamper either.
    c.conn()
        .execute_batch(
            "UPDATE case_meta SET value = 'bogus' WHERE key = 'audit_verified'; \
             UPDATE audit_trail SET reason = 'x' WHERE seq = 1;",
        )
        .unwrap();
    append_is_refused(&c);
    assert!(audit::verify(c.conn()).unwrap().first_bad_seq == Some(1));
}
