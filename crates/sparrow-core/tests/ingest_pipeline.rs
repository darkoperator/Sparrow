use sparrow_core::fixtures;
use sparrow_core::ingest::DEFAULT_MAX_FILE_BYTES;
use sparrow_core::ingest::context::ParseContext;
use sparrow_core::ingest::parser::{ArtifactParser, ParserRegistry};
use sparrow_core::ingest::{FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::readers::text::Span;
use sparrow_core::readers::text::line_spans;
use sparrow_core::{Case, Error, Result};

/// Test parser: every physical line becomes a record in table "test_lines".
struct LinesParser;
impl ArtifactParser for LinesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let text = ctx.text;
        for (n, span) in line_spans(&text.text).into_iter().enumerate() {
            let key = format!("{}:{}", ctx.file_id, n);
            ctx.record_source("test_lines", &key, n as u64, span)?;
            ctx.stats.read += 1;
            ctx.stats.loaded += 1;
        }
        Ok(())
    }
}

/// Test parser that writes provenance, then fails.
struct FailingParser;
impl ArtifactParser for FailingParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let span = line_spans(&ctx.text.text)[0];
        ctx.record_source("test_lines", "doomed", 0, span)?;
        Err(Error::Invalid("boom".into()))
    }
}

/// Test parser: the first physical line is reported as a parse error, the rest load normally.
struct PartiallyFailingParser;
impl ArtifactParser for PartiallyFailingParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        for (n, span) in line_spans(&ctx.text.text).into_iter().enumerate() {
            ctx.stats.read += 1;
            if n == 0 {
                ctx.parse_error(n as u64, span, "bad record")?;
                continue;
            }
            let key = format!("{}:{}", ctx.file_id, n);
            ctx.record_source("test_lines", &key, n as u64, span)?;
            ctx.stats.loaded += 1;
        }
        Ok(())
    }
}

/// Test parser with a reconciliation bug: it reads the first line but never records it as
/// loaded, duplicate or errored.
struct UndercountingParser;
impl ArtifactParser for UndercountingParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        for (n, span) in line_spans(&ctx.text.text).into_iter().enumerate() {
            ctx.stats.read += 1;
            if n == 0 {
                continue;
            }
            let key = format!("{}:{}", ctx.file_id, n);
            ctx.record_source("test_lines", &key, n as u64, span)?;
            ctx.stats.loaded += 1;
        }
        Ok(())
    }
}

fn parsers() -> ParserRegistry {
    let mut r = ParserRegistry::empty();
    r.register("hawk.log", Box::new(LinesParser));
    r.register("inv.logfile", Box::new(LinesParser));
    r.register("hawk.investigate_txt", Box::new(FailingParser));
    r.register("inv.licenses.tenant", Box::new(LinesParser));
    r.register("inv.mailbox_rules", Box::new(LinesParser));
    r.register("inv.transport_rules", Box::new(LinesParser));
    r
}

fn status_of(report: &IngestReport, rel: &str) -> FileStatus {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("{rel} not in report"))
        .status
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn statuses_for_hawk_tree() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    assert_eq!(report.collections.len(), 1);
    assert_eq!(status_of(&report, "Hawk.log"), FileStatus::Parsed);
    assert_eq!(
        status_of(&report, "Tenant/EntraIDUsers.json"),
        FileStatus::NotSupported
    );
    assert_eq!(
        status_of(&report, "notes/random.bin"),
        FileStatus::Unrecognized
    );
    assert_eq!(status_of(&report, "_Investigate.txt"), FileStatus::Error);
    assert!(report.has_errors());
    assert!(
        !report.collections[0]
            .files
            .iter()
            .any(|f| f.rel_path.ends_with(".DS_Store"))
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE record_key LIKE '%:%'"
        ),
        11
    );
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!((f.records_read, f.records_loaded), (11, 11));
    let enc: String = case
        .conn()
        .query_row(
            "SELECT encoding FROM source_files WHERE rel_path = 'Hawk.log'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(enc, "utf-8");
}

#[test]
fn failing_parser_is_rolled_back_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "_Investigate.txt")
        .unwrap();
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("parser hawk.investigate_txt failed") && w.contains("boom"))
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE record_key = 'doomed'"
        ),
        0
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = '_Investigate.txt' AND status = 'error'"
        ),
        1
    );
}

#[test]
fn reingest_same_folder_adds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let files_before = count(&case, "SELECT count(*) FROM source_files");
    let prov_before = count(&case, "SELECT count(*) FROM record_sources");
    let report = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM collections"), 1);
    assert_eq!(
        count(&case, "SELECT count(*) FROM source_files"),
        files_before
    );
    assert_eq!(
        count(&case, "SELECT count(*) FROM record_sources"),
        prov_before
    );
    assert_eq!(status_of(&report, "Hawk.log"), FileStatus::DuplicateFile);
}

#[test]
fn moved_copy_is_marked_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(&dir.path().join("a"));
    fixtures::hawk_tree(&dir.path().join("b"));
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        &dir.path().join("a"),
        &parsers(),
        &IngestOptions::default(),
    )
    .unwrap();
    let prov_before = count(&case, "SELECT count(*) FROM record_sources");
    let report = ingest_path(
        &mut case,
        &dir.path().join("b"),
        &parsers(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM collections"), 2);
    assert_eq!(status_of(&report, "Hawk.log"), FileStatus::DuplicateFile);
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert!(f.warnings[0].starts_with("identical to already-ingested file_id"));
    assert_eq!(
        count(&case, "SELECT count(*) FROM record_sources"),
        prov_before
    );
}

#[test]
fn empty_files_are_not_duplicates_of_each_other() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::invictus_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    for rel in [
        "Case1/Rules/20260910-100700/20260910-100700-MailboxRules.csv",
        "Case1/Rules/20260910-100700/20260910-100700-TransportRules.csv",
    ] {
        assert_eq!(status_of(&report, rel), FileStatus::Parsed, "{rel}");
    }
}

#[test]
fn utf16_log_provenance_uses_raw_byte_offsets_and_editor_lines() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::invictus_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let (line, offset, len): (i64, i64, i64) = case
        .conn()
        .query_row(
            "SELECT rs.line_start, rs.byte_offset, rs.byte_length FROM record_sources rs
             JOIN source_files sf USING (file_id)
             WHERE sf.rel_path = 'LogFile.txt' AND rs.record_ordinal = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let first = fixtures::INVICTUS_LOG.split("\r\n").next().unwrap();
    let second = fixtures::INVICTUS_LOG.split("\r\n").nth(1).unwrap();
    assert_eq!(line, 2);
    assert_eq!(offset as usize, 2 + 2 * (first.len() + 2));
    assert_eq!(len as usize, 2 * second.len());
    let enc: String = case
        .conn()
        .query_row(
            "SELECT encoding FROM source_files WHERE rel_path = 'LogFile.txt'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(enc, "utf-16le");
}

#[test]
fn oversize_files_are_errors_naming_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions {
        max_file_bytes: 10,
        ..IngestOptions::default()
    };
    let report = ingest_path(&mut case, dir.path(), &parsers(), &opts).unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!(f.status, FileStatus::Error);
    assert!(f.warnings[0].contains("--max-file-size"));
}

#[test]
fn path_without_collections_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(dir.path(), "readme.txt", b"hi");
    let mut case = Case::in_memory().unwrap();
    let err =
        ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap_err();
    assert!(err.to_string().contains("no Hawk"));
}

#[test]
fn parse_errors_are_recorded_and_reconciled() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let mut r = ParserRegistry::empty();
    r.register("hawk.log", Box::new(PartiallyFailingParser));
    let report = ingest_path(&mut case, dir.path(), &r, &IngestOptions::default()).unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(
        (f.records_read, f.records_loaded, f.records_error),
        (11, 10, 1)
    );
    assert!(
        f.warnings.is_empty(),
        "no reconciliation mismatch expected: {:?}",
        f.warnings
    );

    let (pe_file_id, pe_line_start): (i64, i64) = case
        .conn()
        .query_row(
            "SELECT pe.file_id, pe.line_start FROM parse_errors pe JOIN source_files sf USING (file_id)
             WHERE sf.rel_path = 'Hawk.log'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(pe_file_id, f.file_id.unwrap());
    assert_eq!(pe_line_start, 1);

    let records_error_db: i64 = case
        .conn()
        .query_row(
            "SELECT records_error FROM source_files WHERE rel_path = 'Hawk.log'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(records_error_db, 1);
}

#[test]
fn undercounted_records_produce_a_reconciliation_mismatch_warning() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let mut r = ParserRegistry::empty();
    r.register("hawk.log", Box::new(UndercountingParser));
    let report = ingest_path(&mut case, dir.path(), &r, &IngestOptions::default()).unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!(f.status, FileStatus::Parsed);
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("reconciliation mismatch")),
        "expected a reconciliation mismatch warning, got {:?}",
        f.warnings
    );
}

#[test]
fn reingest_reports_already_ingested_with_original_file_id() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report1 =
        ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let original_id = report1.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap()
        .file_id
        .unwrap();

    let report2 =
        ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let f = report2.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!(f.status, FileStatus::DuplicateFile);
    assert_eq!(f.file_id, Some(original_id));
    assert_eq!(f.warnings, vec!["already ingested".to_string()]);
}

#[test]
fn failed_file_is_retried_on_next_ingest_once_a_parser_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();

    let mut failing = ParserRegistry::empty();
    failing.register("hawk.investigate_txt", Box::new(FailingParser));
    let report1 = ingest_path(&mut case, dir.path(), &failing, &IngestOptions::default()).unwrap();
    assert_eq!(status_of(&report1, "_Investigate.txt"), FileStatus::Error);

    let mut succeeding = ParserRegistry::empty();
    succeeding.register("hawk.investigate_txt", Box::new(LinesParser));
    let report2 = ingest_path(
        &mut case,
        dir.path(),
        &succeeding,
        &IngestOptions::default(),
    )
    .unwrap();
    assert_eq!(status_of(&report2, "_Investigate.txt"), FileStatus::Parsed);

    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = '_Investigate.txt'"
        ),
        1
    );
}

#[test]
fn not_supported_file_is_retried_once_a_parser_is_added() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();

    let empty = ParserRegistry::empty();
    let report1 = ingest_path(&mut case, dir.path(), &empty, &IngestOptions::default()).unwrap();
    assert_eq!(status_of(&report1, "Hawk.log"), FileStatus::NotSupported);

    let mut with_parser = ParserRegistry::empty();
    with_parser.register("hawk.log", Box::new(LinesParser));
    let report2 = ingest_path(
        &mut case,
        dir.path(),
        &with_parser,
        &IngestOptions::default(),
    )
    .unwrap();
    assert_eq!(status_of(&report2, "Hawk.log"), FileStatus::Parsed);

    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = 'Hawk.log'"
        ),
        1
    );
}

#[cfg(unix)]
#[test]
fn unreadable_file_is_reported_as_error() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let path = dir.path().join(fixtures::HAWK_ROOT_NAME).join("Hawk.log");
    let original = std::fs::metadata(&path).unwrap().permissions();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let can_still_read = std::fs::read(&path).is_ok();
    if can_still_read {
        std::fs::set_permissions(&path, original).unwrap();
        eprintln!(
            "skipping unreadable_file_is_reported_as_error: this process can read a chmod 000 file (running as root?)"
        );
        return;
    }

    let mut case = Case::in_memory().unwrap();
    let result = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default());
    std::fs::set_permissions(&path, original).unwrap();
    let report = result.unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!(f.status, FileStatus::Error);
    assert!(
        f.warnings.iter().any(|w| w.contains("cannot read file")),
        "{:?}",
        f.warnings
    );
}

#[cfg(unix)]
#[test]
fn literal_backslash_tenant_dir_keeps_its_true_rel_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    fixtures::write(&root, "\\Tenant/Simple_x.json", b"[{\"a\":1}]");
    fixtures::write(&root, "Tenant/Simple_x.json", b"[{\"a\":2}]");
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::empty(),
        &IngestOptions::default(),
    )
    .unwrap();
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT rel_path, artifact_type FROM source_files
             WHERE rel_path LIKE '%Simple_x.json' ORDER BY rel_path",
        )
        .unwrap();
    let rows: Vec<(String, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(
        rows,
        vec![
            (
                "Tenant/Simple_x.json".to_string(),
                Some("hawk.tenant.simple_ual".to_string())
            ),
            (
                "\\Tenant/Simple_x.json".to_string(),
                Some("hawk.tenant.simple_ual".to_string())
            ),
        ]
    );
}

#[test]
fn lossy_decoding_is_reported_as_a_file_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    fixtures::write(&root, "Hawk.log", b"caf\xE9 line one\r\nline two\r\n");
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "Hawk.log")
        .unwrap();
    assert_eq!(f.status, FileStatus::Parsed);
    assert!(
        f.warnings
            .iter()
            .any(|w| w == "text decoding was lossy (windows-1252 fallback)"),
        "{:?}",
        f.warnings
    );
    let stored: String = case
        .conn()
        .query_row(
            "SELECT CAST(warnings AS VARCHAR) FROM source_files WHERE rel_path = 'Hawk.log'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(stored.contains("lossy"), "{stored}");
}

#[test]
fn repeated_early_errors_leave_one_row_after_success() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let tiny = IngestOptions {
        max_file_bytes: 10,
        ..IngestOptions::default()
    };
    for _ in 0..2 {
        let r = ingest_path(&mut case, dir.path(), &parsers(), &tiny).unwrap();
        assert_eq!(status_of(&r, "Hawk.log"), FileStatus::Error);
        assert_eq!(
            count(
                &case,
                "SELECT count(*) FROM source_files WHERE rel_path = 'Hawk.log'"
            ),
            1
        );
    }
    let r = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    assert_eq!(status_of(&r, "Hawk.log"), FileStatus::Parsed);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = 'Hawk.log'"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = 'Hawk.log' AND status = 'parsed'"
        ),
        1
    );
}

#[test]
fn identical_files_for_different_subjects_are_both_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let body = b"[]";
    fixtures::write(&root, "bob@contoso.example/InboxRules_x.json", body);
    fixtures::write(&root, "carol@contoso.example/InboxRules_x.json", body);
    let mut r = ParserRegistry::empty();
    r.register("hawk.user.inbox_rules", Box::new(LinesParser));
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &r, &IngestOptions::default()).unwrap();
    for rel in [
        "bob@contoso.example/InboxRules_x.json",
        "carol@contoso.example/InboxRules_x.json",
    ] {
        assert_eq!(status_of(&report, rel), FileStatus::Parsed, "{rel}");
    }
    let subjects = count(
        &case,
        "SELECT count(DISTINCT subject) FROM source_files WHERE rel_path LIKE '%/InboxRules_x.json'",
    );
    assert_eq!(subjects, 2);
}

#[test]
fn record_errors_make_the_report_have_errors() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut r = ParserRegistry::empty();
    r.register("hawk.log", Box::new(PartiallyFailingParser));
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &r, &IngestOptions::default()).unwrap();
    assert_eq!(status_of(&report, "Hawk.log"), FileStatus::Parsed);
    assert!(report.has_errors());
}

#[test]
fn clean_ingest_has_no_errors() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut r = ParserRegistry::empty();
    r.register("hawk.log", Box::new(LinesParser));
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &r, &IngestOptions::default()).unwrap();
    assert!(!report.has_errors());
}

#[cfg(unix)]
#[test]
fn unreadable_directory_is_an_error_row_and_ingest_continues() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let locked = root.join("alice@contoso.example");
    // An unreadable folder next to the collection must not stop discovery either.
    let sibling = dir.path().join("unrelated");
    std::fs::create_dir(&sibling).unwrap();
    let original = std::fs::metadata(&locked).unwrap().permissions();
    let lock = |mode| {
        for d in [&locked, &sibling] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    };
    lock(0o000);
    if std::fs::read_dir(&locked).is_ok() {
        lock(original.mode());
        eprintln!(
            "skipping unreadable_directory_is_an_error_row_and_ingest_continues: chmod 000 directory is still readable (running as root?)"
        );
        return;
    }
    let mut case = Case::in_memory().unwrap();
    let result = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default());
    lock(original.mode());
    let report = result.unwrap();
    assert_eq!(status_of(&report, "Hawk.log"), FileStatus::Parsed);
    let f = status_row(&report, "alice@contoso.example");
    assert_eq!(f.status, FileStatus::Error);
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains("alice@contoso.example")),
        "{:?}",
        f.warnings
    );
    assert!(report.has_errors());
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE rel_path = 'alice@contoso.example' AND status = 'error' AND size_bytes = 0 AND sha256 = ''"
        ),
        1
    );
}

fn status_row<'r>(report: &'r IngestReport, rel: &str) -> &'r sparrow_core::ingest::FileReport {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("{rel} not in report"))
}

#[test]
fn portal_folder_ingests_as_portal_export_collection() {
    let dir = tempfile::tempdir().unwrap();
    let guid = "0f8fad5b-d9cb-469f-a165-70867728950e.csv";
    fixtures::write(
        &dir.path().join("exports"),
        guid,
        b"RecordId,CreationDate,RecordType,Operation,UserId,AuditData\r\n",
    );
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::empty(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert_eq!(
        report.collections[0].tool,
        sparrow_core::discovery::Tool::PortalExport
    );
    let f = status_row(&report, guid);
    assert_eq!(f.artifact_id.as_deref(), Some("portal.ual"));
    assert_eq!(f.status, FileStatus::NotSupported);
    let tool: String = case
        .conn()
        .query_row("SELECT CAST(tool AS VARCHAR) FROM collections", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(tool, "portal_export");
}

#[test]
fn hawk_folder_stamp_is_flagged_as_assumed_utc() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::empty(),
        &IngestOptions::default(),
    )
    .unwrap();
    let assumed: bool = case
        .conn()
        .query_row("SELECT collected_at_tz_assumed FROM collections", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(assumed);
}

/// Test parser that reports an error with a span past the end of the text.
struct BadSpanParser;
impl ArtifactParser for BadSpanParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        ctx.stats.read += 1;
        ctx.parse_error(
            0,
            Span {
                start: 3,
                end: 10_000_000,
            },
            "bad span",
        )
    }
}

#[test]
fn parse_error_with_out_of_range_span_is_clamped() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let mut r = ParserRegistry::empty();
    r.register("hawk.log", Box::new(BadSpanParser));
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &r, &IngestOptions::default()).unwrap();
    assert_eq!(status_row(&report, "Hawk.log").records_error, 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM parse_errors WHERE line_start = 1"
        ),
        1
    );
}

#[test]
fn changed_content_at_the_same_path_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let mut log = fixtures::HAWK_LOG.to_string();
    log.push_str("[2026-09-10 14:31:00Z] - [INFO]   - appended later\r\n");
    fixtures::write(&root, "Hawk.log", log.as_bytes());
    let report = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let f = status_row(&report, "Hawk.log");
    assert_eq!(f.status, FileStatus::Parsed);
    assert!(
        f.warnings[0].contains("content changed"),
        "{:?}",
        f.warnings
    );
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_file_names_are_flagged() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let name = std::ffi::OsStr::from_bytes(b"bad\xffname.txt");
    std::fs::write(root.join("Tenant").join(name), b"x").unwrap();
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &parsers(), &IngestOptions::default()).unwrap();
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path.contains('\u{fffd}'))
        .unwrap();
    assert!(f.warnings.iter().any(|w| w.contains("not valid UTF-8")));
}

#[test]
fn default_max_file_size_is_one_gib() {
    assert_eq!(DEFAULT_MAX_FILE_BYTES, 1 << 30);
}
