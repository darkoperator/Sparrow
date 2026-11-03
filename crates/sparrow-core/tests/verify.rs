use sparrow_core::fixtures;
use sparrow_core::fixtures::{hawk4, portal, ual};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::verify::{source_ref, verify_record};
use sparrow_core::{Case, Error};
#[cfg(unix)]
use sparrow_core::{
    Result,
    ingest::context::ParseContext,
    ingest::parser::{ArtifactParser, InputMode},
    readers::text::line_spans,
};
use std::path::PathBuf;

fn setup() -> (tempfile::TempDir, PathBuf, Case, String) {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let key: String = case
        .conn()
        .query_row(
            "SELECT log_key FROM collection_log WHERE level = 'INVESTIGATE'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    (dir, root, case, key)
}

#[test]
fn intact_record_verifies_with_excerpt_and_source_ref() {
    let (_d, _root, case, key) = setup();
    let rep = verify_record(&case, "collection_log", &key, None).unwrap();
    assert!(rep.ok);
    assert_eq!(rep.sightings.len(), 1);
    let s = &rep.sightings[0];
    assert_eq!(
        s.source_ref,
        format!("{}/Hawk.log:9-10", fixtures::HAWK_ROOT_NAME)
    );
    assert!(
        s.excerpt
            .as_deref()
            .unwrap()
            .ends_with("continued detail line")
    );
}

#[test]
fn change_elsewhere_in_file_fails_file_hash_only() {
    let (_d, root, case, key) = setup();
    let path = root.join("Hawk.log");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replacen("created at", "Created at", 1);
    std::fs::write(&path, text).unwrap();
    let rep = verify_record(&case, "collection_log", &key, None).unwrap();
    assert!(!rep.ok);
    assert!(!rep.sightings[0].file_hash_ok);
    assert!(rep.sightings[0].record_hash_ok);
}

#[test]
fn change_inside_record_fails_record_hash() {
    let (_d, root, case, key) = setup();
    let path = root.join("Hawk.log");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replacen("suspicious", "Suspicious", 1);
    std::fs::write(&path, text).unwrap();
    let rep = verify_record(&case, "collection_log", &key, None).unwrap();
    assert!(!rep.sightings[0].record_hash_ok);
}

#[test]
fn moved_collection_verifies_with_root_override_and_missing_file_is_reported() {
    let (dir, root, case, key) = setup();
    let moved = dir.path().join("moved");
    std::fs::rename(&root, &moved).unwrap();
    let rep = verify_record(&case, "collection_log", &key, None).unwrap();
    assert!(!rep.ok);
    assert!(!rep.sightings[0].file_found);
    let rep = verify_record(&case, "collection_log", &key, Some(&moved)).unwrap();
    assert!(rep.ok);
}

#[test]
fn root_override_relocates_only_the_moved_collection() {
    let dir = tempfile::tempdir().unwrap();
    hawk4::hawk4_tree(&dir.path().join("a"));
    portal::portal_tree(&dir.path().join("b"));
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let moved = dir.path().join("c").join(hawk4::HAWK4_ROOT_NAME);
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::rename(dir.path().join("a").join(hawk4::HAWK4_ROOT_NAME), &moved).unwrap();
    let rep = verify_record(&case, "ual_events", ual::ID_RULE, Some(&moved)).unwrap();
    assert_eq!(rep.sightings.len(), 3);
    assert!(rep.ok, "{rep:?}");
}

#[test]
fn unknown_record_is_not_found() {
    let (_d, _root, case, _key) = setup();
    assert!(matches!(
        verify_record(&case, "collection_log", "nope", None),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn source_ref_formats_single_and_multi_line() {
    assert_eq!(
        source_ref("Hawk_X", "Tenant/a.json", 4, 4),
        "Hawk_X/Tenant/a.json:4"
    );
    assert_eq!(source_ref("Output", "a.csv", 2, 5), "Output/a.csv:2-5");
}

/// Test parser: every physical line becomes a record in table "test_lines".
#[cfg(unix)]
struct LinesParser;
#[cfg(unix)]
impl ArtifactParser for LinesParser {
    fn input(&self) -> InputMode {
        InputMode::Whole
    }

    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        for (n, span) in line_spans(&ctx.whole().unwrap().text.text)
            .into_iter()
            .enumerate()
        {
            let key = format!("{}:{}", ctx.file_id, n);
            let sight = ctx.sighting(span);
            ctx.record_source("test_lines", &key, n as u64, &sight)?;
            ctx.stats.read += 1;
            ctx.stats.loaded += 1;
        }
        Ok(())
    }
}

#[cfg(unix)]
#[test]
fn record_under_literal_backslash_tenant_dir_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    // On Unix a backslash is an ordinary file-name character: this is one component.
    let literal_backslash_tenant = std::ffi::OsStr::new("\\Tenant");
    std::fs::rename(root.join("Tenant"), root.join(literal_backslash_tenant)).unwrap();
    let mut parsers = ParserRegistry::builtin();
    parsers.register("hawk.tenant.entra_users", Box::new(LinesParser));
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, dir.path(), &parsers, &IngestOptions::default()).unwrap();
    let files = &report.collections[0].files;
    let status = |rel: &str| {
        files
            .iter()
            .find(|f| f.rel_path == rel)
            .unwrap_or_else(|| panic!("{rel} not in report: {files:?}"))
            .status
    };
    assert_eq!(status("Hawk.log"), sparrow_core::ingest::FileStatus::Parsed);
    assert_eq!(
        status("\\Tenant/EntraIDUsers.json"),
        sparrow_core::ingest::FileStatus::Parsed
    );
    let key: String = case
        .conn()
        .query_row(
            "SELECT rs.record_key FROM record_sources rs JOIN source_files sf USING (file_id)
             WHERE rs.table_name = 'test_lines' AND sf.rel_path = '\\Tenant/EntraIDUsers.json'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let rep = verify_record(&case, "test_lines", &key, None).unwrap();
    assert!(rep.sightings[0].file_found, "{rep:?}");
    assert!(rep.ok, "{rep:?}");
}

#[test]
fn utf16_log_with_truncated_trailing_byte_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::invictus_tree(dir.path());
    let mut raw = fixtures::utf16le_bom(fixtures::INVICTUS_LOG);
    raw.push(b'x');
    fixtures::write(&root, "LogFile.txt", &raw);
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let (key, offset, length): (String, i64, i64) = case
        .conn()
        .query_row(
            "SELECT cl.log_key, rs.byte_offset, rs.byte_length FROM collection_log cl
             JOIN record_sources rs ON rs.table_name = 'collection_log' AND rs.record_key = cl.log_key
             ORDER BY cl.record_ordinal DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((offset + length) as usize, raw.len());
    let rep = verify_record(&case, "collection_log", &key, None).unwrap();
    assert!(rep.sightings[0].file_hash_ok, "{rep:?}");
    assert!(rep.sightings[0].record_hash_ok, "{rep:?}");
    assert!(rep.ok);
}
