use sparrow_core::discovery::runs::{earliest_run_stamp, run_dirs};
use sparrow_core::discovery::{Tool, discover_collections};
use sparrow_core::fixtures;
use sparrow_core::ingest::context::ParseContext;
use sparrow_core::ingest::parser::{ArtifactParser, InputMode, ParserRegistry};
use sparrow_core::ingest::{
    EMPTY_FILE_WARNING, FileReport, FileStatus, IngestOptions, IngestReport, ingest_path,
};
use sparrow_core::readers::text::{is_blank_content, line_spans};
use sparrow_core::{Case, Result};
use std::path::{Path, PathBuf};

/// Every physical line is a record (stands in for the UAL parser until Task 3).
struct LinesParser;
impl ArtifactParser for LinesParser {
    fn input(&self) -> InputMode {
        InputMode::Whole
    }

    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let text = ctx.whole().unwrap().text;
        for (n, span) in line_spans(&text.text).into_iter().enumerate() {
            let key = format!("{}:{}", ctx.file_id, n);
            let sight = ctx.sighting(span);
            ctx.record_source("test_lines", &key, n as u64, &sight)?;
            ctx.stats.read += 1;
            ctx.stats.loaded += 1;
        }
        Ok(())
    }
}

fn lines_registry() -> ParserRegistry {
    let mut r = ParserRegistry::empty();
    r.register("inv.ual.window", Box::new(LinesParser));
    r.register("inv.ual.merged", Box::new(LinesParser));
    r
}

fn ingest(base: &Path, parsers: &ParserRegistry) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, base, parsers, &IngestOptions::default()).unwrap();
    (case, report)
}

fn row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("no report row for {rel}"))
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

const WINDOW: &str = "UnifiedAuditLog/20260910-100000/UAL-20260801000000-20260901000000.csv";
const MERGED: &str = "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv";

/// An Output root shaped like the real sample: runs, empty run folders, 0-byte and
/// BOM-only exports, a nested Mailbox Audit Log run.
fn output_root(base: &Path) -> PathBuf {
    let root = base.join("CASE_OUTPUT");
    fixtures::write(&root, WINDOW, b"a\r\nb\r\n");
    fixtures::write(
        &root,
        "EntraID/20260910-100100-SignInLogs/servicePrincipal/20260910100105-servicePrincipal-SignInLogs.json",
        b"[]\r\n",
    );
    std::fs::create_dir_all(root.join("EntraID/20260910-100100-SignInLogs/managedIdentity"))
        .unwrap();
    fixtures::write(
        &root,
        "Users/20260910-100300/20260910-100300-Users.csv",
        b"",
    );
    fixtures::write(
        &root,
        "Groups/20260910-100600/20260910-100600-Groups.csv",
        &[0xEF, 0xBB, 0xBF],
    );
    std::fs::create_dir_all(root.join("Rules/20260910-100400")).unwrap();
    std::fs::create_dir_all(
        root.join("Mailbox Audit Log/20260910-100500/UnifiedAuditLog/20260910-100501"),
    )
    .unwrap();
    fixtures::write(&root, "Rules/20260910-100400/.DS_Store", b"junk");
    root
}

#[test]
fn blank_content_is_empty_or_bom_and_whitespace() {
    assert!(is_blank_content(b""));
    assert!(is_blank_content(&[0xEF, 0xBB, 0xBF]));
    assert!(is_blank_content(&[0xFF, 0xFE, b'\r', 0, b'\n', 0]));
    assert!(is_blank_content(b"\r\n"));
    assert!(!is_blank_content(b"\"a\"\r\n"));
    assert!(!is_blank_content(&[0xEF, 0xBB, 0xBF, b'[', b']']));
    // NUL is the high byte of UTF-16 whitespace, not blank on its own: an all-NUL file
    // without a UTF-16 BOM is corrupt, not empty.
    assert!(is_blank_content(&[0xFE, 0xFF, 0, b'\r', 0, b'\n']));
    assert!(!is_blank_content(&[0, 0, 0, 0]));
    assert!(!is_blank_content(&[0xEF, 0xBB, 0xBF, 0, 0]));
}

#[test]
fn run_dirs_describe_every_run_folder() {
    let dir = tempfile::tempdir().unwrap();
    let root = output_root(dir.path());
    let runs = run_dirs(&root);
    let find = |rel: &str| {
        runs.iter()
            .find(|r| r.rel_dir == rel)
            .unwrap_or_else(|| panic!("no run dir {rel}: {runs:#?}"))
    };
    let ual = find("UnifiedAuditLog/20260910-100000");
    assert_eq!(ual.component.as_deref(), Some("UnifiedAuditLog"));
    assert_eq!(ual.stamp, "20260910-100000");
    assert_eq!(ual.label, None);
    assert_eq!((ual.files, ual.empty_files, ual.bytes), (1, 0, 6));

    let signins = find("EntraID/20260910-100100-SignInLogs");
    assert_eq!(signins.label.as_deref(), Some("SignInLogs"));
    assert_eq!(signins.files, 0);
    let mi = find("EntraID/20260910-100100-SignInLogs/managedIdentity");
    assert_eq!(mi.component.as_deref(), Some("EntraID"));
    assert_eq!(mi.stamp, "20260910-100100");
    assert_eq!(mi.files, 0);

    assert_eq!(find("Users/20260910-100300").empty_files, 1);
    assert_eq!(find("Groups/20260910-100600").empty_files, 1);
    // .DS_Store is not a collector file.
    assert_eq!(find("Rules/20260910-100400").files, 0);

    let nested = find("Mailbox Audit Log/20260910-100500/UnifiedAuditLog/20260910-100501");
    assert_eq!(nested.component.as_deref(), Some("Mailbox Audit Log"));
    assert_eq!(nested.stamp, "20260910-100501");
    // Component folders themselves are not runs.
    assert!(runs.iter().all(|r| r.rel_dir != "UnifiedAuditLog"));
}

#[test]
fn collection_time_is_the_earliest_run() {
    let dir = tempfile::tempdir().unwrap();
    let root = output_root(dir.path());
    assert_eq!(
        earliest_run_stamp(&root).as_deref(),
        Some("20260910_100000")
    );
    let found = discover_collections(dir.path()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].tool, Tool::Invictus);
    assert_eq!(found[0].started_hint.as_deref(), Some("20260910_100000"));
}

#[test]
fn empty_files_warn_and_runs_are_recorded() {
    let dir = tempfile::tempdir().unwrap();
    output_root(dir.path());
    let (case, report) = ingest(dir.path(), &ParserRegistry::builtin());
    for rel in [
        "Users/20260910-100300/20260910-100300-Users.csv",
        "Groups/20260910-100600/20260910-100600-Groups.csv",
    ] {
        let f = row(&report, rel);
        assert_ne!(f.status, FileStatus::Error, "{rel}");
        assert!(
            f.warnings.iter().any(|w| w == EMPTY_FILE_WARNING),
            "{rel}: {:?}",
            f.warnings
        );
    }
    assert!(
        !row(&report, WINDOW)
            .warnings
            .iter()
            .any(|w| w == EMPTY_FILE_WARNING)
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_runs WHERE files = 0 AND rel_dir = 'Rules/20260910-100400'"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_runs WHERE empty_files = 1 AND component = 'Users'"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT epoch(run_stamp)::BIGINT FROM collector_runs WHERE rel_dir = 'UnifiedAuditLog/20260910-100000'"
        ),
        1_789_034_400
    );
    assert_eq!(
        count(&case, "SELECT epoch(collected_at)::BIGINT FROM collections"),
        1_789_034_400
    );
    // Re-ingest replaces the rows instead of adding more.
    let before = count(&case, "SELECT count(*) FROM collector_runs");
    let mut case = case;
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM collector_runs"), before);
}

#[test]
fn merged_copy_is_superseded_by_its_window_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = output_root(dir.path());
    fixtures::write(&root, MERGED, b"a\r\nb\r\n");
    let (_case, report) = ingest(dir.path(), &lines_registry());
    assert_eq!(row(&report, WINDOW).status, FileStatus::Parsed);
    let merged = row(&report, MERGED);
    assert_eq!(merged.status, FileStatus::SkippedSuperseded);
    assert!(merged.warnings[0].contains(WINDOW), "{:?}", merged.warnings);
}

#[test]
fn merged_copy_alone_is_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("OUT");
    fixtures::write(&root, MERGED, b"a\r\nb\r\n");
    let (_case, report) = ingest(dir.path(), &lines_registry());
    let merged = row(&report, MERGED);
    assert_eq!(merged.status, FileStatus::Parsed);
    assert_eq!(merged.records_loaded, 2);
}

#[test]
fn merged_rule_only_applies_to_derived_files_below_a_merged_folder() {
    use sparrow_core::ingest::supersede::Handled;
    let mut h = Handled::default();
    h.insert("EntraID/20260910-100100-SignInLogs/servicePrincipal/p1.json");
    assert_eq!(
        h.superseded_by(
            "EntraID/20260910-100100-SignInLogs/servicePrincipal/Merged/SignInLogs-servicePrincipal-Combined.json",
            true
        )
        .as_deref(),
        Some("EntraID/20260910-100100-SignInLogs/servicePrincipal/p1.json")
    );
    // Not derived: never superseded by the Merged rule.
    assert_eq!(
        h.superseded_by(
            "EntraID/20260910-100100-SignInLogs/servicePrincipal/Merged/x.json",
            false
        ),
        None
    );
    // A file in a sibling folder does not count.
    assert_eq!(
        h.superseded_by(
            "EntraID/20260910-100100-SignInLogs/managedIdentity/Merged/x.json",
            true
        ),
        None
    );
}

#[test]
fn collection_created_without_a_time_gains_the_earliest_run_on_reingest() {
    let dir = tempfile::tempdir().unwrap();
    output_root(dir.path());
    let (mut case, _) = ingest(dir.path(), &ParserRegistry::builtin());
    // As created before run stamps were known.
    case.conn()
        .execute(
            "UPDATE collections SET collected_at = NULL, collected_at_tz_assumed = false",
            [],
        )
        .unwrap();
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert_eq!(
        count(&case, "SELECT epoch(collected_at)::BIGINT FROM collections"),
        1_789_034_400
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collections WHERE collected_at_tz_assumed"
        ),
        1
    );
}

#[test]
fn merged_copy_is_kept_when_a_file_beside_its_folder_failed() {
    use sparrow_core::ingest::supersede::Handled;
    let merged = "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv";
    let mut h = Handled::default();
    h.insert("UnifiedAuditLog/20260910-100000/UAL-1.csv");
    // A failure in another folder does not matter.
    h.insert_failed("UnifiedAuditLog/20260910-110000/UAL-1.csv");
    h.insert_failed("UnifiedAuditLog/20260910-100000/Merged/Other.csv");
    assert!(h.superseded_by(merged, true).is_some());
    h.insert_failed("UnifiedAuditLog/20260910-100000/UAL-2.csv");
    assert_eq!(h.superseded_by(merged, true), None);
    // A file deferred and later handled no longer counts as failed.
    h.insert("UnifiedAuditLog/20260910-100000/UAL-2.csv");
    assert!(h.superseded_by(merged, true).is_some());
}
