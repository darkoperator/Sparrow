use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileStatus, IngestOptions, ingest_path};
use sparrow_core::readers::time::DateOrder;

fn ingest_hawk(
    opts: &IngestOptions,
) -> (tempfile::TempDir, Case, sparrow_core::ingest::IngestReport) {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &ParserRegistry::builtin(), opts).unwrap();
    (dir, case, report)
}

#[test]
fn hawk_log_entries_levels_and_continuations() {
    let (_d, case, report) = ingest_hawk(&IngestOptions::default());
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!((f.records_read, f.records_loaded), (10, 10));
    let (level, message, ts, tz): (String, String, String, bool) = case
        .conn()
        .query_row(
            "SELECT level, message, CAST(ts AS VARCHAR), tz_assumed FROM collection_log WHERE record_ordinal = 8",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(level, "INVESTIGATE");
    assert_eq!(
        message,
        "Found suspicious inbox rule\ncontinued detail line"
    );
    assert_eq!(ts, "2026-09-10 14:20:00+00");
    assert!(!tz);
    let (ls, le): (i64, i64) = case
        .conn()
        .query_row(
            "SELECT line_start, line_end FROM record_sources WHERE table_name = 'collection_log' AND record_ordinal = 8",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((ls, le), (9, 10));
    let untagged: Option<String> = case
        .conn()
        .query_row(
            "SELECT level FROM collection_log WHERE record_ordinal = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(untagged, None);
}

#[test]
fn hawk_metadata_updates_collection_and_warns_on_ambiguous_window() {
    let (_d, case, report) = ingest_hawk(&IngestOptions::default());
    let (version, tenant, start): (String, String, Option<String>) = case
        .conn()
        .query_row(
            "SELECT tool_version, tenant_name_reported, CAST(window_start AS VARCHAR) FROM collections",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(version, "4.0.0");
    assert_eq!(tenant, "Contoso_Ltd");
    assert_eq!(start, None);
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert!(
        f.warnings
            .iter()
            .any(|w| w.starts_with("collection window not parsed") && w.contains("--culture"))
    );
}

#[test]
fn hawk_window_parsed_with_culture() {
    let opts = IngestOptions {
        date_order: Some(DateOrder::MonthFirst),
        ..IngestOptions::default()
    };
    let (_d, case, _r) = ingest_hawk(&opts);
    let (start, end, collected): (String, String, String) = case
        .conn()
        .query_row(
            "SELECT CAST(window_start AS VARCHAR), CAST(window_end AS VARCHAR), CAST(collected_at AS VARCHAR) FROM collections",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(start, "2026-06-12 00:00:00+00");
    assert_eq!(end, "2026-09-11 00:00:00+00");
    assert_eq!(collected, "2026-09-10 14:15:00+00");
}

#[test]
fn invictus_utf16_log_with_levels_and_assumed_timezone() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::invictus_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let rows: Vec<(Option<String>, String, String, bool)> = {
        let mut stmt = case
            .conn()
            .prepare("SELECT level, message, CAST(ts AS VARCHAR), tz_assumed FROM collection_log ORDER BY record_ordinal")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1].0.as_deref(), Some("WARNING"));
    assert_eq!(rows[1].1, "Mailbox audit bypass lookup failed");
    assert_eq!(rows[1].2, "2026-09-10 10:00:05+00");
    assert!(rows[1].3);
    assert_eq!(rows[0].0, None);
}
