use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::verify::{source_ref, verify_record};
use sparrow_core::{Case, Error};
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
