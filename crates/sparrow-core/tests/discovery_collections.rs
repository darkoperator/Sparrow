use sparrow_core::discovery::{Tool, discover_collections};
use sparrow_core::fixtures;

#[test]
fn finds_hawk_and_invictus_under_a_parent_folder() {
    let dir = tempfile::tempdir().unwrap();
    let hawk = fixtures::hawk_tree(dir.path());
    let inv = fixtures::invictus_tree(&dir.path().join("evidence"));
    let found = discover_collections(dir.path()).unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].tool, Tool::Hawk);
    assert_eq!(found[0].root, hawk);
    assert_eq!(found[0].tenant_hint.as_deref(), Some("Contoso_Ltd"));
    assert_eq!(found[0].started_hint.as_deref(), Some("20260910_141500"));
    assert_eq!(found[1].tool, Tool::Invictus);
    assert_eq!(found[1].root, inv);
}

#[test]
fn accepts_the_collection_root_itself() {
    let dir = tempfile::tempdir().unwrap();
    let hawk = fixtures::hawk_tree(dir.path());
    let found = discover_collections(&hawk).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].root, hawk);
}

#[test]
fn invictus_custom_output_dir_without_logfile_is_found_by_components() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("custom");
    fixtures::write(
        &root,
        "MFA/20260910-100000/20260910-100000-AuthenticationMethods.csv",
        b"user\r\n",
    );
    let found = discover_collections(dir.path()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].tool, Tool::Invictus);
    assert_eq!(found[0].root, root);
}

#[test]
fn folder_named_like_hawk_without_log_or_tenant_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(dir.path(), "Hawk_Foo_20260101_000000/readme.txt", b"hi");
    assert!(discover_collections(dir.path()).unwrap().is_empty());
}

#[test]
fn file_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(dir.path(), "a.txt", b"x");
    assert!(discover_collections(&dir.path().join("a.txt")).is_err());
}

#[test]
#[cfg(unix)]
fn detects_hawk_root_with_literal_backslash_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let hawk_root = dir.path().join("Hawk_Foo_20260101_000000");
    fixtures::write(&hawk_root, "\\Tenant/x.csv", b"data");
    let found = discover_collections(dir.path()).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].tool, Tool::Hawk);
    assert_eq!(found[0].root, hawk_root);
    assert_eq!(found[0].tenant_hint.as_deref(), Some("Foo"));
    assert_eq!(found[0].started_hint.as_deref(), Some("20260101_000000"));
}
