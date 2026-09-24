use sparrow_core::db::migrations::latest_version;
use sparrow_core::{Case, Error};

fn tables(case: &Case) -> Vec<String> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT table_name FROM duckdb_tables() WHERE schema_name = 'main' ORDER BY table_name",
        )
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn fresh_case_has_provenance_tables() {
    let case = Case::in_memory().unwrap();
    assert_eq!(
        tables(&case),
        vec![
            "collection_log",
            "collections",
            "parse_errors",
            "record_sources",
            "schema_migrations",
            "source_files"
        ]
    );
    assert_eq!(case.schema_version().unwrap(), latest_version());
}

#[test]
fn tables_and_columns_are_documented() {
    let case = Case::in_memory().unwrap();
    let missing: i64 = case
        .conn()
        .query_row(
            "SELECT count(*) FROM duckdb_columns() WHERE schema_name = 'main' AND database_name = current_database()
               AND table_name <> 'schema_migrations' AND (comment IS NULL OR comment = '')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(missing, 0, "every column needs COMMENT ON COLUMN");
    let c: String = case
        .conn()
        .query_row(
            "SELECT comment FROM duckdb_tables() WHERE table_name = 'record_sources'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(c.contains("line"));
}

#[test]
fn file_status_enum_rejects_unknown_values() {
    let case = Case::in_memory().unwrap();
    let err = case.conn().execute_batch(
        "INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('hawk', '/x', '0.1.0');
         INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status) VALUES (1, 'a', 0, '', 'bogus');",
    );
    assert!(err.is_err());
}

#[test]
fn reopening_is_idempotent_and_read_only_open_works() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.duckdb");
    drop(Case::create_or_open(&path).unwrap());
    let case = Case::create_or_open(&path).unwrap();
    let n: i64 = case
        .conn()
        .query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n as u32, latest_version());
    drop(case);
    let ro = Case::open_read_only(&path).unwrap();
    assert!(ro.is_read_only());
    assert!(
        ro.conn()
            .execute_batch("INSERT INTO parse_errors VALUES (1,0,1,1,0,0,'x',NULL)")
            .is_err()
    );
}

#[test]
fn newer_schema_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.duckdb");
    {
        let case = Case::create_or_open(&path).unwrap();
        case.conn()
            .execute_batch("INSERT INTO schema_migrations (version, name) VALUES (999, 'future')")
            .unwrap();
    }
    assert!(matches!(
        Case::create_or_open(&path),
        Err(Error::SchemaTooNew { db: 999, .. })
    ));
    assert!(matches!(
        Case::open_read_only(&path),
        Err(Error::SchemaTooNew { db: 999, .. })
    ));
}

#[test]
fn read_only_open_of_outdated_schema_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.duckdb");
    {
        let conn = duckdb::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
        )
        .unwrap();
    }
    let err = Case::open_read_only(&path).err().unwrap();
    assert!(matches!(err, Error::SchemaOutdated { db: 0, .. }));
    assert!(err.to_string().contains("sparrow upgrade"));
}

#[test]
fn read_only_open_of_missing_file_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Case::open_read_only(&dir.path().join("nope.duckdb")),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn describe_lists_tables_columns_and_comments() {
    let case = Case::in_memory().unwrap();
    let all = sparrow_core::db::describe(&case, None).unwrap();
    assert!(all.iter().any(|t| t.table == "record_sources"));
    let one = sparrow_core::db::describe(&case, Some("source_files")).unwrap();
    assert_eq!(one.len(), 1);
    assert!(one[0].comment.as_deref().unwrap().contains("SHA-256"));
    let sha = one[0].columns.iter().find(|c| c.name == "sha256").unwrap();
    assert_eq!(sha.data_type, "VARCHAR");
    assert!(sha.comment.is_some());
    assert!(
        sparrow_core::db::describe(&case, Some("nope"))
            .unwrap()
            .is_empty()
    );
}
