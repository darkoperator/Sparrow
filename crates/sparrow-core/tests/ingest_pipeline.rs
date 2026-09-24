use sparrow_core::fixtures;
use sparrow_core::ingest::context::ParseContext;
use sparrow_core::ingest::parser::{ArtifactParser, ParserRegistry};
use sparrow_core::ingest::{FileStatus, IngestOptions, IngestReport, ingest_path};
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
    assert!(
        err.to_string()
            .contains("no Hawk or Microsoft-Extractor-Suite output")
    );
}
