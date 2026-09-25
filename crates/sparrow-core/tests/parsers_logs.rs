use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::fixtures::csv_line;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileStatus, IngestOptions, ingest_path};
use sparrow_core::readers::time::DateOrder;
use std::path::Path;

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

#[test]
fn unparseable_log_timestamps_are_warned_about() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap");
    sparrow_core::fixtures::write(
        &root,
        "Hawk.log",
        b"[2026-13-45 10:00:00Z] - bad month\r\n[2026-09-10 14:15:00Z] - ok\r\n",
    );
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("1 log entries have timestamps that could not be parsed")),
        "{:?}",
        f.warnings
    );
}

fn ingest_dir(base: &Path) -> (Case, sparrow_core::ingest::IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        base,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    (case, report)
}

fn log_rows(case: &Case, file: &str) -> Vec<(Option<String>, String, i64, bool)> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT l.level, l.message, epoch(l.ts)::BIGINT, l.tz_assumed FROM collection_log l
             JOIN source_files s ON s.file_id = l.file_id WHERE s.rel_path = ? ORDER BY l.record_ordinal",
        )
        .unwrap();
    stmt.query_map([file], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn hawk3_log_culture_times_tags_sections_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap3");
    fixtures::write(
        &root,
        "Hawk.log",
        &fixtures::utf16le_bom(concat!(
            "[9/14/2026 2:15:00 PM] - *** Version 3.1.0 ***\r\n",
            "[9/14/2026 2:15:01 PM] - ## Tenant ## - Starting tenant investigation\r\n",
            "[9/14/2026 2:15:02 PM] - [WARNING] - Mailbox auditing is off\r\n",
            "    for 2 mailboxes\r\n",
            "[9/14/2026 2:15:03 PM] - [ACTION] - Collecting inbox rules\r\n",
        )),
    );
    let (case, report) = ingest_dir(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        log_rows(&case, "Hawk.log"),
        vec![
            (None, "*** Version 3.1.0 ***".to_string(), 1789395300, true),
            (
                None,
                "## Tenant ## - Starting tenant investigation".to_string(),
                1789395301,
                true
            ),
            (
                Some("WARNING".to_string()),
                "Mailbox auditing is off\n    for 2 mailboxes".to_string(),
                1789395302,
                true
            ),
            (
                Some("ACTION".to_string()),
                "Collecting inbox rules".to_string(),
                1789395303,
                true
            ),
        ]
    );
    let version: String = case
        .conn()
        .query_row("SELECT tool_version FROM collections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, "3.1.0");
    let (ls, le): (i64, i64) = case
        .conn()
        .query_row(
            "SELECT line_start, line_end FROM record_sources WHERE table_name = 'collection_log' AND record_ordinal = 2",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((ls, le), (3, 4));
}

#[test]
fn hawk3_log_with_only_ambiguous_times_uses_the_collection_order() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap3");
    fixtures::write(
        &root,
        "Hawk.log",
        b"[9/10/2026 2:15:00 PM] - *** Version 3.1.0 ***\r\n",
    );
    let evidence = csv_line(&["CreationTime", "Id", "Operation", "Workload", "UserId"])
        + &csv_line(&[
            "9/15/2026 8:30:00 AM",
            "e2e2e2e2-0000-4000-8000-000000000002",
            "SearchExported",
            "SecurityComplianceCenter",
            "admin@contoso.example",
        ]);
    fixtures::write(&root, "Tenant/eDiscoveryLogs.csv", evidence.as_bytes());
    let (case, report) = ingest_dir(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(log_rows(&case, "Hawk.log")[0].2, 1789049700);
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("other files of this collection")),
        "{:?}",
        f.warnings
    );
}

#[test]
fn hawk3_log_without_any_order_keeps_null_times() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap3");
    fixtures::write(
        &root,
        "Hawk.log",
        b"[9/10/2026 2:15:00 PM] - *** Version 3.1.0 ***\r\n",
    );
    let (case, report) = ingest_dir(dir.path());
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!(f.status, FileStatus::Parsed);
    assert!(
        f.warnings
            .iter()
            .any(|w| w.starts_with("log entry times not parsed") && w.contains("--culture")),
        "{:?}",
        f.warnings
    );
    let ts: Option<String> = case
        .conn()
        .query_row("SELECT CAST(ts AS VARCHAR) FROM collection_log", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(ts, None);
}

#[test]
fn hawk4_prompt_lines_keep_their_level() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap4");
    fixtures::write(
        &root,
        "Hawk.log",
        concat!(
            "[2026-09-10 14:15:03Z] - [PROMPT] -  Please provide the start date\r\n",
            "[2026-09-10 14:15:04Z] - [ERROR]  - Could not connect\r\n",
        )
        .as_bytes(),
    );
    let (case, _report) = ingest_dir(dir.path());
    assert_eq!(
        log_rows(&case, "Hawk.log"),
        vec![
            (
                Some("PROMPT".to_string()),
                "Please provide the start date".to_string(),
                1789049703,
                false
            ),
            (
                Some("ERROR".to_string()),
                "Could not connect".to_string(),
                1789049704,
                false
            ),
        ]
    );
}

#[test]
fn psframework_log_rows_load_into_collection_log() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap3");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    let header = csv_line(&[
        "ComputerName",
        "File",
        "FunctionName",
        "Level",
        "Line",
        "Message",
        "ModuleName",
        "Runspace",
        "Tags",
        "TargetObject",
        "Timestamp",
        "Type",
        "Username",
    ]);
    let row = |level: &str, message: &str, ts: &str| {
        csv_line(&[
            "WS01",
            "Start-HawkTenantInvestigation.ps1",
            "Out-LogFile",
            level,
            "12",
            message,
            "HAWK",
            "1",
            "",
            "",
            ts,
            "Information",
            "CONTOSO\\analyst",
        ])
    };
    let csv = header
        + &row("Host", "Starting", "2026-09-02 08:00:00.123")
        + &row("Warning", "@{Name=x}", "2026-09-02 08:05:00.000");
    fixtures::write(&root, "2026-09-02_logs.csv", &fixtures::utf8_bom(&csv));
    let (case, report) = ingest_dir(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        log_rows(&case, "2026-09-02_logs.csv"),
        vec![
            (
                Some("HOST".to_string()),
                "Starting".to_string(),
                1788336000,
                true
            ),
            (
                Some("WARNING".to_string()),
                "@{Name=x}".to_string(),
                1788336300,
                true
            ),
        ]
    );
    let line: i64 = case
        .conn()
        .query_row(
            "SELECT rs.line_start FROM record_sources rs JOIN source_files s ON s.file_id = rs.file_id
             WHERE s.rel_path = '2026-09-02_logs.csv' AND rs.record_ordinal = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(line, 3);
}

#[test]
fn psframework_file_without_log_columns_is_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap3");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    fixtures::write(
        &root,
        "2026-09-03_logs.csv",
        (csv_line(&["A", "B"]) + &csv_line(&["1", "2"])).as_bytes(),
    );
    let (_case, report) = ingest_dir(dir.path());
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "2026-09-03_logs.csv")
        .unwrap();
    assert_eq!(f.status, FileStatus::NotSupported, "{f:#?}");
}

fn hawk_log_report(
    report: &sparrow_core::ingest::IngestReport,
) -> &sparrow_core::ingest::FileReport {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == "Hawk.log")
        .expect("Hawk.log report row")
}

#[test]
fn hawk3_log_from_a_year_first_culture_splits_into_entries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap3");
    fixtures::write(
        &root,
        "Hawk.log",
        &fixtures::utf16le_bom(concat!(
            "[2026-09-14 14:15:00] - *** Version 3.1.0 ***\r\n",
            "[2026/09/14 14:15:01] - [WARNING] - x\r\n",
        )),
    );
    let (case, report) = ingest_dir(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        log_rows(&case, "Hawk.log"),
        vec![
            (None, "*** Version 3.1.0 ***".to_string(), 1789395300, true),
            (
                Some("WARNING".to_string()),
                "x".to_string(),
                1789395301,
                true
            ),
        ]
    );
    let version: String = case
        .conn()
        .query_row("SELECT tool_version FROM collections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, "3.1.0");
    let f = hawk_log_report(&report);
    assert!(
        !f.warnings.iter().any(|w| w.contains("no line matched")),
        "{:?}",
        f.warnings
    );
}

#[test]
fn hawk_licence_line_becomes_a_low_confidence_licence_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(sparrow_core::fixtures::HAWK_ROOT_NAME);
    sparrow_core::fixtures::write(
        &root,
        "Hawk.log",
        sparrow_core::fixtures::HAWK_LOG.as_bytes(),
    );
    let mut case = sparrow_core::Case::in_memory().unwrap();
    let report = sparrow_core::ingest::ingest_path(
        &mut case,
        dir.path(),
        &sparrow_core::ingest::parser::ParserRegistry::builtin(),
        &sparrow_core::ingest::IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
    let row: (String, String, String, Option<String>) = case
        .conn()
        .query_row(
            "SELECT record_key, license_tier, CAST(confidence AS VARCHAR), sku_part_number FROM licenses",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        ("1|hawk_log|e5".into(), "E5".into(), "low".into(), None)
    );
    let line: i64 = case
        .conn()
        .query_row(
            "SELECT line_start FROM record_sources WHERE table_name = 'licenses'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(line, 7);
}

#[test]
fn hawk_log_without_a_licence_line_writes_no_licence_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(sparrow_core::fixtures::HAWK_ROOT_NAME);
    sparrow_core::fixtures::write(
        &root,
        "Hawk.log",
        b"[2026-09-10 14:15:00Z] - [INFO]   - Failed to detect license type. Max days of log retention is unknown.\r\n",
    );
    let mut case = sparrow_core::Case::in_memory().unwrap();
    sparrow_core::ingest::ingest_path(
        &mut case,
        dir.path(),
        &sparrow_core::ingest::parser::ParserRegistry::builtin(),
        &sparrow_core::ingest::IngestOptions::default(),
    )
    .unwrap();
    let n: i64 = case
        .conn()
        .query_row("SELECT count(*) FROM licenses", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn hawk_log_in_an_unknown_format_is_warned_about() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("cap3");
    fixtures::write(
        &root,
        "Hawk.log",
        b"14.09.2026 T14:15:00 | Version 3.1.0\r\n14.09.2026 T14:15:01 | x\r\n",
    );
    let (_case, report) = ingest_dir(dir.path());
    let f = hawk_log_report(&report);
    assert!(
        f.warnings.iter().any(|w| w
            == "no line matched a known Hawk log format; the log was stored as one untimed entry"),
        "{:?}",
        f.warnings
    );
}
