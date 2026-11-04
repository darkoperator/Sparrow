//! One file's rows are staged once (insert-only TEMP tables) and merged once (Task 2b): no per-batch merge, no
//! staging churn inside the file's transaction, no stage table left behind, and the same rows and counts as one
//! batch of everything.

use duckdb::params;
use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::db::state_tables::INBOX_RULES;
use sparrow_core::ingest::bulk::{LoadOutcome, StagedUal, UalFileStage, load_ual_batch};
use sparrow_core::ingest::state::{self, StagedRow, StateFileStage, load_rows};
use sparrow_core::normalize::ual::{UalRecord, normalize_audit};
use sparrow_core::normalize::ual_shape::{detect_shape, to_audit};
use sparrow_core::readers::text::SourcePos;
use sparrow_core::readers::time::DateOrder;

const MIA: &str = "a2222222-2222-4222-8222-222222222222";

fn rec(v: Value, lossy: bool) -> UalRecord {
    let map = v.as_object().unwrap().clone();
    let shape = detect_shape(map.keys().map(String::as_str), false);
    normalize_audit(
        &to_audit(shape, &map, lossy).unwrap(),
        Some(DateOrder::MonthFirst),
    )
    .unwrap()
}

fn mia_full() -> UalRecord {
    rec(
        json!({
            "CreationTime": "2026-09-01T10:05:00", "Id": MIA, "Operation": "MailItemsAccessed",
            "Workload": "Exchange", "RecordType": 50, "UserId": "alice@contoso.example",
            "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind"}],
            "Folders": [{"Path": "\\Inbox", "FolderItems": [
                {"InternetMessageId": "<m1@contoso.example>", "SizeInBytes": 1},
                {"InternetMessageId": "<m2@contoso.example>", "SizeInBytes": 2}
            ]}]
        }),
        false,
    )
}

fn mia_partial() -> UalRecord {
    rec(
        json!({
            "CreationTime": "2026-09-01T10:05:00", "Id": MIA, "Operation": "MailItemsAccessed",
            "Folders": "System.Object[]"
        }),
        true,
    )
}

/// A distinct rule record `i` whose AuditData is about `pad` bytes.
fn generated(i: u64, pad: usize) -> UalRecord {
    rec(
        json!({
            "CreationTime": "2026-09-01T10:00:00",
            "Id": format!("{:08x}-0000-4000-8000-{:012x}", i, i),
            "Operation": "New-InboxRule", "RecordType": 1, "Workload": "Exchange",
            "Pad": "x".repeat(pad)
        }),
        false,
    )
}

fn staged(ordinal: u64, rec: UalRecord) -> StagedUal {
    StagedUal {
        ordinal,
        pos: SourcePos {
            line_start: ordinal as u32 + 2,
            line_end: ordinal as u32 + 2,
            byte_offset: ordinal * 100,
            byte_length: 100,
        },
        raw_sha256: format!("sha{ordinal}"),
        rec,
    }
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn temp_tables(conn: &duckdb::Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare(
            "SELECT table_name FROM duckdb_tables() WHERE temporary
             UNION ALL SELECT view_name FROM duckdb_views() WHERE temporary AND NOT internal
             ORDER BY 1",
        )
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn ual_snapshot(case: &Case) -> Vec<String> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT 'e|' || record_id || '|' || collection_id || '|' || data_completeness || '|' || audit_data::VARCHAR
                 FROM ual_events
             UNION ALL SELECT 'm|' || record_id || '|' || item_ordinal || '|' || collection_id || '|'
                 || coalesce(internet_message_id, '') FROM mail_items_accessed
             UNION ALL SELECT 's|' || table_name || '|' || record_key || '|' || file_id || '|' || record_ordinal || '|'
                 || line_start || '|' || byte_offset || '|' || raw_sha256 FROM record_sources
             ORDER BY 1",
        )
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn ual_stage_leaves_no_temp_tables() {
    let case = Case::in_memory().unwrap();
    assert_eq!(temp_tables(case.conn()), Vec::<String>::new());
    for file_id in [1, 2] {
        let mut stage = UalFileStage::begin(case.conn(), file_id).unwrap();
        for b in 0..3u64 {
            let rows: Vec<StagedUal> = (0..5)
                .map(|i| {
                    let n = b * 5 + i;
                    staged(n, generated(n, 10))
                })
                .collect();
            stage.stage(&rows).unwrap();
        }
        let out = stage.finish(7).unwrap();
        assert_eq!(out.staged, 15);
        assert_eq!(
            temp_tables(case.conn()),
            Vec::<String>::new(),
            "file {file_id}"
        );
    }
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 15);
    assert_eq!(count(&case, "SELECT count(*) FROM record_sources"), 30);
}

#[test]
fn ual_stage_never_deletes_staged_rows() {
    let mut case = Case::in_memory().unwrap();
    let tx = case.conn_mut().transaction().unwrap();
    let mut stage = UalFileStage::begin(&tx, 1).unwrap();
    for b in 0..50u64 {
        let rows: Vec<StagedUal> = (0..200)
            .map(|i| {
                let n = b * 200 + i;
                staged(n, generated(n, 4096))
            })
            .collect();
        stage.stage(&rows).unwrap();
    }
    let staged_rows: i64 = tx
        .query_row("SELECT count(*) FROM stage_ual", [], |r| r.get(0))
        .unwrap();
    assert_eq!(staged_rows, 10_000);
    // `duckdb_tables().estimated_size` reads 0 for an uncommitted TEMP table, so the rows are counted.
    let other: i64 = tx
        .query_row(
            "SELECT (SELECT count(*) FROM stage_mia) + (SELECT count(*) FROM stage_file)
                  + (SELECT count(*) FROM stage_sharing) + (SELECT count(*) FROM stage_search)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(other, 0, "rule records have no child rows");
    let names = temp_tables(&tx);
    for merged in [
        "stage_chosen",
        "stage_chosen_keys",
        "stage_fresh",
        "stage_upgrade",
        "stage_written",
        "file_inserted",
    ] {
        assert!(
            !names.iter().any(|n| n == merged),
            "{merged} exists before finish: {names:?}"
        );
    }
    let evidence: i64 = tx
        .query_row("SELECT count(*) FROM ual_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(evidence, 0, "nothing merged before finish");
    let out = stage.finish(7).unwrap();
    assert_eq!(
        out,
        LoadOutcome {
            staged: 10_000,
            inserted: 10_000,
            upgraded: 0
        }
    );
    assert_eq!(temp_tables(&tx), Vec::<String>::new());
    tx.commit().unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 10_000);
}

#[test]
fn ual_finish_counts_like_one_batch() {
    type Make = fn() -> UalRecord;
    let orders: [(&str, Make, Make); 4] = [
        ("partial,full", mia_partial, mia_full),
        ("full,partial", mia_full, mia_partial),
        ("full,full", mia_full, mia_full),
        ("partial,partial", mia_partial, mia_partial),
    ];
    for prior in [false, true] {
        for (name, x, y) in orders {
            let name = format!("{name}, stored by an earlier file: {prior}");
            let setup = |case: &Case| {
                if prior {
                    load_ual_batch(case.conn(), 7, 1, &[staged(0, mia_partial())]).unwrap();
                }
            };
            let one = Case::in_memory().unwrap();
            setup(&one);
            let whole =
                load_ual_batch(one.conn(), 7, 2, &[staged(0, x()), staged(1, y())]).unwrap();
            let two = Case::in_memory().unwrap();
            setup(&two);
            let mut stage = UalFileStage::begin(two.conn(), 2).unwrap();
            stage.stage(&[staged(0, x())]).unwrap();
            stage.stage(&[staged(1, y())]).unwrap();
            let split = stage.finish(7).unwrap();
            assert_eq!(split, whole, "{name}");
            assert_eq!(ual_snapshot(&one), ual_snapshot(&two), "{name}");
        }
    }
    // The stored-partial case really upgrades (the comparison above is not vacuous).
    let case = Case::in_memory().unwrap();
    load_ual_batch(case.conn(), 7, 1, &[staged(0, mia_partial())]).unwrap();
    let mut stage = UalFileStage::begin(case.conn(), 2).unwrap();
    stage.stage(&[staged(0, mia_partial())]).unwrap();
    stage.stage(&[staged(1, mia_full())]).unwrap();
    assert_eq!(
        stage.finish(8).unwrap(),
        LoadOutcome {
            staged: 2,
            inserted: 0,
            upgraded: 1
        }
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed WHERE internet_message_id IS NOT NULL"
        ),
        2
    );
}

#[test]
fn ual_stage_rolled_back_leaves_nothing() {
    let mut case = Case::in_memory().unwrap();
    for finish in [false, true] {
        let tx = case.conn_mut().transaction().unwrap();
        let mut stage = UalFileStage::begin(&tx, 1).unwrap();
        stage.stage(&[staged(0, mia_full())]).unwrap();
        stage.stage(&[staged(1, generated(1, 10))]).unwrap();
        if finish {
            assert_eq!(stage.finish(7).unwrap().inserted, 2);
        }
        // Without `finish` the stage is abandoned (a cancelled or failed file); either way the transaction rolls back.
        drop(tx);
        assert_eq!(
            count(&case, "SELECT count(*) FROM ual_events"),
            0,
            "{finish}"
        );
        assert_eq!(count(&case, "SELECT count(*) FROM mail_items_accessed"), 0);
        assert_eq!(count(&case, "SELECT count(*) FROM record_sources"), 0);
        assert_eq!(temp_tables(case.conn()), Vec::<String>::new(), "{finish}");
    }
}

// ---- state tables ----

fn collection(case: &Case) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO collections (tool, root_path, collected_at, sparrow_version)
             VALUES ('hawk', '/cases/a', NULL, 't') RETURNING collection_id",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

fn file(case: &Case, collection_id: i64) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status)
             VALUES (?, 'x.json', 1, 'h', 'parsed') RETURNING file_id",
            params![collection_id],
            |r| r.get(0),
        )
        .unwrap()
}

const RULE_COLS: &[&str] = &["kind", "mailbox", "rule_identity", "name", "priority"];

fn rule(ord: u64, key: &str, name: &str) -> StagedRow {
    StagedRow {
        ordinal: ord,
        pos: SourcePos {
            line_start: 1 + ord as u32,
            line_end: 1 + ord as u32,
            byte_offset: ord * 10,
            byte_length: 10,
        },
        raw_sha256: format!("sha{ord}"),
        record_key: key.into(),
        cells: vec![
            Some("inbox".into()),
            Some("alice".into()),
            Some("1".into()),
            Some(name.into()),
            Some("0".into()),
        ],
        raw: Some(format!("{{\"Name\":\"{name}\",\"Ord\":{ord}}}")),
        tz_assumed: Vec::new(),
    }
}

fn state_snapshot(case: &Case) -> Vec<String> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT 'r|' || record_key || '|' || name || '|' || collection_id || '|' || raw::VARCHAR || '|'
                 || column_collections::VARCHAR FROM inbox_rules
             UNION ALL SELECT 's|' || table_name || '|' || record_key || '|' || file_id || '|' || record_ordinal || '|'
                 || line_start || '|' || raw_sha256 FROM record_sources
             ORDER BY 1",
        )
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn state_finish_equals_one_load_rows() {
    // k1 repeats across batches (the first copy wins), k3 updates a row an earlier file stored (latest wins), and
    // the tail row k2 collides with an earlier streamed row (it loses, as across batches).
    let batches: Vec<Vec<StagedRow>> = vec![
        vec![rule(0, "k1", "First"), rule(1, "k2", "Move")],
        vec![rule(2, "k1", "Second"), rule(3, "k3", "New")],
        vec![rule(4, "k2", "Tail"), rule(5, "k4", "Fresh")],
    ];
    let prepare = |case: &Case| -> (i64, i64) {
        let c = collection(case);
        let f0 = file(case, c);
        load_rows(
            case.conn(),
            &INBOX_RULES,
            RULE_COLS,
            c,
            f0,
            &[rule(9, "k3", "Old")],
        )
        .unwrap();
        (c, file(case, c))
    };
    let one = Case::in_memory().unwrap();
    let (c, f) = prepare(&one);
    let all: Vec<StagedRow> = batches.iter().flatten().cloned().collect();
    let whole = load_rows(one.conn(), &INBOX_RULES, RULE_COLS, c, f, &all).unwrap();
    assert_eq!(
        whole,
        state::LoadOutcome {
            staged: 6,
            inserted: 3,
            updated: 1
        }
    );
    let three = Case::in_memory().unwrap();
    let (c, f) = prepare(&three);
    let mut stage = StateFileStage::begin(three.conn(), &INBOX_RULES, RULE_COLS, f).unwrap();
    for b in &batches {
        stage.stage(b).unwrap();
    }
    let split = stage.finish(c).unwrap();
    assert_eq!(split, whole);
    assert_eq!(state_snapshot(&one), state_snapshot(&three));
    let names: String = three
        .conn()
        .query_row(
            "SELECT string_agg(record_key || '=' || name, ',' ORDER BY record_key) FROM inbox_rules",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(names, "k1=First,k2=Move,k3=New,k4=Fresh");
}

#[test]
fn state_stage_leaves_no_temp_tables() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case);
    for _ in 0..2 {
        let f = file(&case, c);
        let mut stage = StateFileStage::begin(case.conn(), &INBOX_RULES, RULE_COLS, f).unwrap();
        for b in 0..3u64 {
            let rows: Vec<StagedRow> = (0..4)
                .map(|i| {
                    let n = b * 4 + i;
                    rule(n, &format!("k{n}"), "R")
                })
                .collect();
            stage.stage(&rows).unwrap();
        }
        assert_eq!(stage.finish(c).unwrap().staged, 12);
        assert_eq!(temp_tables(case.conn()), Vec::<String>::new());
    }
    assert_eq!(count(&case, "SELECT count(*) FROM inbox_rules"), 12);
    // `load_rows` leaves none either.
    let f = file(&case, c);
    load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        c,
        f,
        &[rule(0, "k0", "R")],
    )
    .unwrap();
    assert_eq!(temp_tables(case.conn()), Vec::<String>::new());
}
