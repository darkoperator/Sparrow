//! `record_sources` has no key index (migration 30), so its writers keep `(table_name, record_key, file_id,
//! record_ordinal)` unique themselves: duplicates within one file's rows (first in staging order wins), a second
//! writer or flush of the same file, deferred and retried files and superseded copies. The writer tests (state,
//! second writer, UAL) exercise the deduplication itself; the ingest tests (deferred, superseded, re-import) are
//! regression guards for the file-id argument: no writer may see another attempt's rows. The re-import parses
//! nothing (every file is a duplicate), and Hawk.log's second flush finds nothing queued, so neither exercises the
//! deduplication.

use duckdb::params;
use sparrow_core::Case;
use sparrow_core::db::state_tables::INBOX_RULES;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::bulk::{StagedUal, load_ual_batch};
use sparrow_core::ingest::context::{ParseContext, RecordSource};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::state::{StagedRow, StateFileStage};
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::normalize::ual::normalize_audit;
use sparrow_core::normalize::ual_shape::{detect_shape, to_audit};
use sparrow_core::readers::stream::{Admitted, Sight};
use sparrow_core::readers::text::SourcePos;
use sparrow_core::readers::time::DateOrder;
use std::path::Path;

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// Fails unless every sighting's four key columns are unique and every sighting belongs to a parsed file.
fn assert_unique(case: &Case) {
    let (all, distinct): (i64, i64) = case
        .conn()
        .query_row(
            "SELECT count(*), count(DISTINCT (table_name, record_key, file_id, record_ordinal)) FROM record_sources",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(all, distinct, "duplicate sightings");
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM record_sources rs
             WHERE NOT EXISTS (SELECT 1 FROM source_files sf WHERE sf.file_id = rs.file_id AND sf.status = 'parsed')"
        ),
        0,
        "a sighting of a file that is not a parsed file"
    );
}

/// `table|rel_path|ordinal|line_start` of every sighting, sorted (the record key is left out: it is a hash).
fn sightings(case: &Case) -> Vec<String> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT rs.table_name || '|' || sf.rel_path || '|' || rs.record_ordinal || '|' || rs.line_start
             FROM record_sources rs JOIN source_files sf ON sf.file_id = rs.file_id ORDER BY 1",
        )
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn ingest(case: &mut Case, base: &Path) -> IngestReport {
    ingest_path(
        case,
        base,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap()
}

fn row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    let found: Vec<&FileReport> = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .filter(|f| f.rel_path == rel)
        .collect();
    assert_eq!(found.len(), 1, "{rel}: {found:#?}");
    found[0]
}

const USERS: &str = "Tenant/AzureADUsers.csv";

/// A Hawk capture whose user list (one ambiguous date) waits for the order the eDiscovery summary proves: the user
/// list is deferred, rolled back and parsed again on the retry pass (a regression guard). Hawk.log's sightings are
/// flushed by the parser and the ingest's final flush is then a no-op (the
/// parser's own flush and the ingest's final one).
fn deferred_capture(base: &Path) {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    let users = csv_line(&[
        "UserPrincipalname",
        "ObjectID",
        "UserType",
        "DateCreated",
        "UserStateChangedOn",
        "DirSyncEnabled",
    ]) + &csv_line(&[
        "alice@contoso.example",
        "11111111-1111-4111-8111-111111111111",
        "Member",
        "9/2/2026 8:00:00 AM",
        "",
        "",
    ]);
    fixtures::write(&root, USERS, &fixtures::utf8_bom(&users));
    let ediscovery = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "Workload",
        "UserId",
        "Case",
        "CaseID",
        "Cmdlet",
    ]) + &csv_line(&[
        "9/15/2026 8:30:00 AM",
        "e2e2e2e2-0000-4000-8000-000000000002",
        "SearchExported",
        "SecurityComplianceCenter",
        "admin@contoso.example",
        "Case 1",
        "e1e1e1e1-0000-4000-8000-000000000001",
        "New-ComplianceSearchAction",
    ]);
    fixtures::write(
        &root,
        "Tenant/eDiscoveryLogs.csv",
        &fixtures::utf8_bom(&ediscovery),
    );
}

#[test]
fn a_deferred_then_retried_file_has_one_sighting_per_record() {
    let dir = tempfile::tempdir().unwrap();
    deferred_capture(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest(&mut case, dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let users = row(&report, USERS);
    assert_eq!(
        (users.status, users.records_loaded),
        (FileStatus::Parsed, 1)
    );
    // It was retried: its dates came from the other files of the collection.
    assert!(
        users
            .warnings
            .iter()
            .any(|w| w.contains("other files of this collection")),
        "{:?}",
        users.warnings
    );
    assert_unique(&case);
    let all = sightings(&case);
    let users_rows: Vec<&String> = all.iter().filter(|s| s.starts_with("users|")).collect();
    assert_eq!(users_rows, vec!["users|Tenant/AzureADUsers.csv|0|2"]);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = 'Tenant/AzureADUsers.csv'"
        ),
        1
    );
    let logs = all
        .iter()
        .filter(|s| s.starts_with("collection_log|Hawk.log|"))
        .count() as i64;
    assert!(logs > 0, "{all:?}");
    assert_eq!(
        logs,
        count(&case, "SELECT count(*) FROM collection_log"),
        "one sighting per log entry"
    );
}

/// An Extractor Suite UAL run: one window's dates are all ambiguous (deferred, retried), the other proves
/// month-first, and the Merged copy of both is superseded by them.
fn ual_run(base: &Path) -> (String, String, String) {
    let root = base.join("Output");
    let header = csv_line(&[
        "CreationTime",
        "Id",
        "Operation",
        "RecordType",
        "UserId",
        "Workload",
    ]);
    let record = |time: &str, id: &str| {
        csv_line(&[time, id, "Update", "2", "alice@contoso.example", "Exchange"])
    };
    let r1 = record(
        "8/9/2026 10:00:00 AM",
        "e4e4e4e4-0000-4000-8000-000000000004",
    );
    let r2 = record(
        "8/15/2026 10:00:00 AM",
        "e5e5e5e5-0000-4000-8000-000000000005",
    );
    let run = "UnifiedAuditLog/20260910-100000";
    let ambiguous = format!("{run}/UAL-20260809000000-20260810000000.csv");
    let decisive = format!("{run}/UAL-20260815000000-20260816000000.csv");
    let merged = format!("{run}/Merged/UAL-Combined.csv");
    fixtures::write(&root, &ambiguous, format!("{header}{r1}").as_bytes());
    fixtures::write(&root, &decisive, format!("{header}{r2}").as_bytes());
    fixtures::write(&root, &merged, format!("{header}{r1}{r2}").as_bytes());
    (ambiguous, decisive, merged)
}

#[test]
fn a_superseded_copy_adds_no_sightings_and_retried_windows_one_each() {
    let dir = tempfile::tempdir().unwrap();
    let (ambiguous, decisive, merged) = ual_run(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest(&mut case, dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(row(&report, &merged).status, FileStatus::SkippedSuperseded);
    assert_unique(&case);
    assert_eq!(
        sightings(&case),
        vec![
            format!("ual_events|{ambiguous}|0|2"),
            format!("ual_events|{decisive}|0|2")
        ]
    );
}

#[test]
fn regression_guard_re_importing_the_same_files_into_the_same_case_adds_no_sightings() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    deferred_capture(&data);
    ual_run(&data);
    let path = dir.path().join("case.duckdb");
    let first = {
        let mut case = Case::create_or_open(&path).unwrap();
        let report = ingest(&mut case, &data);
        assert!(!report.has_errors(), "{report:#?}");
        assert_unique(&case);
        sightings(&case)
    };
    assert!(first.len() > 3, "{first:?}");
    let mut case = Case::create_or_open(&path).unwrap();
    let report = ingest(&mut case, &data);
    assert!(!report.has_errors(), "{report:#?}");
    let reparsed: Vec<&FileReport> = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .filter(|f| f.status == FileStatus::Parsed)
        .collect();
    assert!(reparsed.is_empty(), "{reparsed:#?}");
    assert_unique(&case);
    assert_eq!(sightings(&case), first);
}

// ---- The writers, one file at a time ----

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

fn pos(line: u32) -> SourcePos {
    SourcePos {
        line_start: line,
        line_end: line,
        byte_offset: u64::from(line) * 10,
        byte_length: 10,
    }
}

const RULE_COLS: &[&str] = &["kind", "mailbox", "rule_identity", "name", "priority"];

/// Inbox rule `key` at record `ord`, read at `line`.
fn rule(ord: u64, key: &str, line: u32) -> StagedRow {
    StagedRow {
        ordinal: ord,
        pos: pos(line),
        raw_sha256: format!("sha{line}"),
        record_key: key.into(),
        cells: vec![
            Some("inbox".into()),
            Some("alice".into()),
            Some("1".into()),
            Some(format!("R{line}")),
            Some("0".into()),
        ],
        raw: Some(format!("{{\"Line\":{line}}}")),
        tz_assumed: Vec::new(),
    }
}

/// `table|key|file|ordinal|line_start|raw_sha256` of every sighting, sorted.
fn rows(case: &Case) -> Vec<String> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT concat_ws('|', table_name, record_key, file_id, record_ordinal, line_start, raw_sha256)
             FROM record_sources ORDER BY 1",
        )
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn a_state_file_staging_a_record_twice_keeps_its_first_sighting() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case);
    let f = file(&case, c);
    let mut stage = StateFileStage::begin(case.conn(), &INBOX_RULES, RULE_COLS, f).unwrap();
    // (k1, 0) is staged three times (twice in the first batch, once in the second) with other spans; the first
    // staged, at line 2, wins, though a later copy has a smaller line (1): staging order decides, not the line.
    // (k1, 1) is the same key at another ordinal: its own sighting.
    stage
        .stage(&[rule(0, "k1", 2), rule(0, "k1", 1), rule(1, "k1", 4)])
        .unwrap();
    stage.stage(&[rule(0, "k1", 5), rule(2, "k2", 6)]).unwrap();
    stage.finish(c).unwrap();
    assert_unique(&case);
    assert_eq!(
        rows(&case),
        vec![
            format!("inbox_rules|k1|{f}|0|2|sha2"),
            format!("inbox_rules|k1|{f}|1|4|sha4"),
            format!("inbox_rules|k2|{f}|2|6|sha6"),
        ]
    );
}

#[test]
fn a_second_writer_of_the_same_file_adds_only_new_sightings() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case);
    let f = file(&case, c);
    // A sighting the file flushed first (line 9), then a stage of the same table holding it again (line 2).
    let raw = b"x".to_vec();
    let opts = IngestOptions::default();
    let admitted = Admitted::from_bytes(Path::new("x.json"), &raw);
    {
        let mut ctx = ParseContext::new(
            case.conn(),
            c,
            f,
            "x.json",
            None,
            &admitted,
            RecordSource::Memory(&raw),
            None,
            &opts,
        );
        let sight = Sight {
            pos: pos(9),
            raw_sha256: "sha9".into(),
        };
        ctx.queue_source("inbox_rules", "k1", 0, &sight);
        ctx.flush_sources().unwrap();
        // A second flush of the same sighting and a per-row write of it add nothing either.
        ctx.queue_source("inbox_rules", "k1", 0, &sight);
        ctx.flush_sources().unwrap();
        ctx.record_source("inbox_rules", "k1", 0, &sight).unwrap();
    }
    for _ in 0..2 {
        let mut stage = StateFileStage::begin(case.conn(), &INBOX_RULES, RULE_COLS, f).unwrap();
        stage.stage(&[rule(0, "k1", 2), rule(3, "k3", 7)]).unwrap();
        stage.finish(c).unwrap();
    }
    // Another file's sighting of the same record and ordinal is its own row.
    let g = file(&case, c);
    let mut stage = StateFileStage::begin(case.conn(), &INBOX_RULES, RULE_COLS, g).unwrap();
    stage.stage(&[rule(0, "k1", 2)]).unwrap();
    stage.finish(c).unwrap();
    assert_unique(&case);
    assert_eq!(
        rows(&case),
        vec![
            format!("inbox_rules|k1|{f}|0|9|sha9"),
            format!("inbox_rules|k1|{g}|0|2|sha2"),
            format!("inbox_rules|k3|{f}|3|7|sha7"),
        ]
    );
}

fn ual(id: &str) -> sparrow_core::normalize::ual::UalRecord {
    let v = serde_json::json!({
        "CreationTime": "2026-09-01T10:00:00", "Id": id, "Operation": "New-InboxRule", "RecordType": 1,
        "Workload": "Exchange"
    });
    let map = v.as_object().unwrap().clone();
    let shape = detect_shape(map.keys().map(String::as_str), false);
    normalize_audit(
        &to_audit(shape, &map, false).unwrap(),
        Some(DateOrder::MonthFirst),
    )
    .unwrap()
}

fn staged_ual(ord: u64, line: u32, id: &str) -> StagedUal {
    StagedUal {
        ordinal: ord,
        pos: pos(line),
        raw_sha256: format!("sha{line}"),
        rec: ual(id),
    }
}

#[test]
fn a_ual_file_loaded_twice_keeps_its_first_sightings() {
    const A: &str = "a1111111-1111-4111-8111-111111111111";
    const B: &str = "b2222222-2222-4222-8222-222222222222";
    let case = Case::in_memory().unwrap();
    let c = collection(&case);
    let f = file(&case, c);
    // The UAL merge itself needs a (record, ordinal) once per load (`stage_chosen` joins on it), so the duplicates
    // come from a second load for the same file: (A, 0) and (A, 1) again with other spans (the first stay), and B at
    // a new ordinal (its own sighting).
    load_ual_batch(
        case.conn(),
        c,
        f,
        &[
            staged_ual(0, 2, A),
            staged_ual(1, 4, A),
            staged_ual(2, 6, B),
        ],
    )
    .unwrap();
    load_ual_batch(
        case.conn(),
        c,
        f,
        &[
            staged_ual(0, 3, A),
            staged_ual(1, 5, A),
            staged_ual(3, 7, B),
        ],
    )
    .unwrap();
    assert_unique(&case);
    assert_eq!(
        rows(&case),
        vec![
            format!("ual_events|{A}|{f}|0|2|sha2"),
            format!("ual_events|{A}|{f}|1|4|sha4"),
            format!("ual_events|{B}|{f}|2|6|sha6"),
            format!("ual_events|{B}|{f}|3|7|sha7"),
        ]
    );
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 2);
}
