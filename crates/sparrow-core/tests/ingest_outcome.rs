//! `IngestReport::outcome`: records the collector lost are told apart from real problems.

use sparrow_core::Case;
use sparrow_core::fixtures::{self, invictus};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{
    FileReport, FileStatus, IngestOptions, IngestOutcome, IngestReport, ingest_path,
};
use std::path::Path;

fn ingest(base: &Path) -> IngestReport {
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        base,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap()
}

fn file<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("{rel} not in {report:#?}"))
}

#[test]
fn a_collector_placeholder_alone_is_collector_loss_only() {
    let dir = tempfile::tempdir().unwrap();
    invictus::roles_tree(dir.path(), true);
    let report = ingest(dir.path());
    let f = file(&report, invictus::ROLES_ALL);
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(
        (f.records_read, f.records_loaded, f.records_error),
        (2, 1, 1)
    );
    assert_eq!(f.records_collector_lost, 1);
    assert!(
        report.has_errors(),
        "a lost record is still something wrong"
    );
    assert_eq!(report.outcome(), IngestOutcome::CollectorLossOnly);
}

#[test]
fn a_clean_tree_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    invictus::roles_tree(dir.path(), false);
    let report = ingest(dir.path());
    let f = file(&report, invictus::ROLES_ALL);
    assert_eq!((f.records_loaded, f.records_error), (1, 0));
    assert_eq!(f.records_collector_lost, 0);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(report.outcome(), IngestOutcome::Clean);
}

#[test]
fn a_real_parse_error_beside_a_collector_loss_is_a_problem() {
    let dir = tempfile::tempdir().unwrap();
    invictus::roles_tree(dir.path(), true);
    fixtures::hawk_unparseable_trace_tree(dir.path());
    let report = ingest(dir.path());
    assert_eq!(report.collections.len(), 2, "{report:#?}");
    assert_eq!(file(&report, invictus::ROLES_ALL).records_collector_lost, 1);
    let t = file(&report, fixtures::HAWK_TRACE);
    assert_eq!((t.records_loaded, t.records_error), (1, 1), "{t:#?}");
    assert_eq!(t.records_collector_lost, 0);
    assert_eq!(report.outcome(), IngestOutcome::Problems);
}

fn report_of(f: FileReport) -> IngestReport {
    IngestReport {
        collections: vec![sparrow_core::ingest::CollectionReport {
            collection_id: 1,
            tool: sparrow_core::discovery::Tool::Hawk,
            root: "r".into(),
            files: vec![f],
        }],
    }
}

fn parsed(error: u64, lost: u64) -> FileReport {
    FileReport {
        file_id: Some(1),
        rel_path: "f.csv".into(),
        artifact_id: None,
        status: FileStatus::Parsed,
        records_read: 5,
        records_loaded: 5 - error,
        records_duplicate: 0,
        records_error: error,
        records_collector_lost: lost,
        warnings: Vec::new(),
    }
}

#[test]
fn problems_win_over_collector_loss() {
    // Some rejected records were lost by the collector, the rest were not.
    assert_eq!(report_of(parsed(2, 1)).outcome(), IngestOutcome::Problems);
    assert_eq!(
        report_of(parsed(2, 2)).outcome(),
        IngestOutcome::CollectorLossOnly
    );
    assert_eq!(report_of(parsed(0, 0)).outcome(), IngestOutcome::Clean);
    // A reconciliation mismatch is a problem even when the only rejected record was lost.
    let mut f = parsed(1, 1);
    f.warnings
        .push("reconciliation mismatch: read 5, loaded 3".into());
    assert_eq!(report_of(f).outcome(), IngestOutcome::Problems);
    // A failed file is a problem whatever its counts.
    let mut f = parsed(1, 1);
    f.status = FileStatus::Error;
    assert_eq!(report_of(f).outcome(), IngestOutcome::Problems);
}
