use sparrow_core::fixtures;
use sparrow_core::fixtures::{hawk4, portal, ual};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::verify::{SourceReader, source_ref, verify_record, verify_record_with};
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

/// A reader over file bytes that fails any read touching bytes before `poison_before`.
struct PoisonedPrefix {
    data: std::io::Cursor<Vec<u8>>,
    poison_before: u64,
}

impl std::io::Read for PoisonedPrefix {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.data.position() < self.poison_before {
            return Err(std::io::Error::other("bytes before the record were read"));
        }
        self.data.read(buf)
    }
}

impl std::io::Seek for PoisonedPrefix {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.data.seek(pos)
    }
}

#[test]
fn verify_does_not_read_whole_file() {
    let (_d, _root, case, key) = setup();
    let (offset, length): (i64, i64) = case
        .conn()
        .query_row(
            "SELECT byte_offset, byte_length FROM record_sources WHERE table_name = 'collection_log' AND record_key = ?",
            [&key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(offset > 0 && length > 0);
    let opener = move |p: &std::path::Path| -> std::io::Result<Box<dyn SourceReader>> {
        Ok(Box::new(PoisonedPrefix {
            data: std::io::Cursor::new(std::fs::read(p)?),
            poison_before: offset as u64,
        }))
    };
    let rep = verify_record_with(&case, "collection_log", &key, None, &opener).unwrap();
    let s = &rep.sightings[0];
    assert!(s.file_found);
    assert!(
        s.record_hash_ok,
        "record check must only read the record: {rep:?}"
    );
    assert!(
        s.excerpt
            .as_deref()
            .unwrap()
            .ends_with("continued detail line"),
        "{rep:?}"
    );
    // Hashing the whole file does read the poisoned prefix and fails closed.
    assert!(!s.file_hash_ok);
    assert!(!rep.ok);
}

#[test]
fn record_past_the_end_of_the_file_fails_the_record_hash_without_panicking() {
    let (_d, root, case, key) = setup();
    let path = root.join("Hawk.log");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    let rep = verify_record(&case, "collection_log", &key, None).unwrap();
    assert!(rep.sightings[0].file_found);
    assert!(!rep.sightings[0].file_hash_ok);
    assert!(!rep.sightings[0].record_hash_ok);
}

#[test]
fn utf16le_record_verifies_and_shows_decoded_text() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::invictus_tree(dir.path());
    let raw = fixtures::utf16le_bom(fixtures::INVICTUS_LOG);
    fixtures::write(&root, "LogFile.txt", &raw);
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let (key, message): (String, String) = case
        .conn()
        .query_row(
            "SELECT cl.log_key, cl.message FROM collection_log cl ORDER BY cl.record_ordinal DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let rep = verify_record(&case, "collection_log", &key, None).unwrap();
    assert!(rep.ok, "{rep:?}");
    let excerpt = rep.sightings[0].excerpt.as_deref().unwrap();
    assert!(
        !excerpt.contains('\0') && !excerpt.contains('\u{FFFD}'),
        "{excerpt:?}"
    );
    assert!(
        excerpt.contains(message.trim()),
        "{excerpt:?} vs {message:?}"
    );
}

/// A reader that adds every byte it returns to a shared count.
struct Counted {
    data: std::io::Cursor<Vec<u8>>,
    read: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl std::io::Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.data.read(buf)?;
        self.read
            .fetch_add(n as u64, std::sync::atomic::Ordering::SeqCst);
        Ok(n)
    }
}

impl std::io::Seek for Counted {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.data.seek(pos)
    }
}

/// A record seen twice in one file: the file's hash is computed once per verify, not once per sighting.
#[test]
fn a_file_with_several_sightings_of_the_record_is_hashed_once() {
    let (_d, root, case, key) = setup();
    case.conn()
        .execute(
            "INSERT INTO record_sources
             SELECT table_name, record_key, file_id, record_ordinal + 1000, line_start, line_end, byte_offset,
                    byte_length, raw_sha256
             FROM record_sources WHERE table_name = 'collection_log' AND record_key = ?",
            [&key],
        )
        .unwrap();
    let length: i64 = case
        .conn()
        .query_row(
            "SELECT max(byte_length) FROM record_sources WHERE table_name = 'collection_log' AND record_key = ?",
            [&key],
            |r| r.get(0),
        )
        .unwrap();
    let size = std::fs::metadata(root.join("Hawk.log")).unwrap().len();
    let read = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let r = read.clone();
    let opener = move |p: &std::path::Path| -> std::io::Result<Box<dyn SourceReader>> {
        Ok(Box::new(Counted {
            data: std::io::Cursor::new(std::fs::read(p)?),
            read: r.clone(),
        }))
    };
    let rep = verify_record_with(&case, "collection_log", &key, None, &opener).unwrap();
    assert_eq!(rep.sightings.len(), 2);
    assert!(rep.ok, "{rep:?}");
    assert!(
        rep.sightings
            .iter()
            .all(|s| s.file_hash_ok && s.record_hash_ok)
    );
    // Each sighting reads its record; the whole file is read once.
    assert_eq!(
        read.load(std::sync::atomic::Ordering::SeqCst),
        size + 2 * length as u64
    );
}

/// An empty record placed past the end of its file (its hash, of nothing, matches) still fails: it is not in the
/// file.
#[test]
fn an_empty_record_past_the_end_of_the_file_fails_the_record_hash() {
    let (_d, root, case, key) = setup();
    let size = std::fs::metadata(root.join("Hawk.log")).unwrap().len();
    case.conn()
        .execute(
            "UPDATE record_sources SET byte_offset = ? + 10, byte_length = 0, raw_sha256 = sha256('')
             WHERE table_name = 'collection_log' AND record_key = ?",
            duckdb::params![size as i64, &key],
        )
        .unwrap();
    let rep = verify_record(&case, "collection_log", &key, None).unwrap();
    assert!(rep.sightings[0].file_found);
    assert!(rep.sightings[0].file_hash_ok, "the file itself is intact");
    assert!(!rep.sightings[0].record_hash_ok);
    assert!(!rep.ok);
}
