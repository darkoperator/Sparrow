use sparrow_core::db::migrations::latest_version;
use sparrow_core::db::state_tables::{ALL, LoadMode};
use sparrow_core::{Case, Error};

fn data_type(case: &Case, table: &str, column: &str) -> Option<String> {
    case.conn()
        .query_row(
            "SELECT data_type FROM duckdb_columns()
             WHERE database_name = current_database() AND table_name = ? AND column_name = ?",
            duckdb::params![table, column],
            |r| r.get(0),
        )
        .ok()
}

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
            "app_credentials",
            "audit_config",
            "collection_log",
            "collections",
            "collector_flags",
            "file_events",
            "inbox_rules",
            "mail_items_accessed",
            "mailboxes",
            "mobile_devices",
            "oauth_grants",
            "parse_errors",
            "record_sources",
            "remote_domains",
            "risk_detections",
            "risky_users",
            "role_assignments",
            "schema_migrations",
            "search_queries",
            "sharing_events",
            "source_files",
            "tenant_settings",
            "transport_rules",
            "ual_events",
            "users"
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

#[test]
fn collector_tool_accepts_portal_export() {
    let case = Case::in_memory().unwrap();
    case.conn()
        .execute(
            "INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('portal_export', '/x', 't')",
            [],
        )
        .unwrap();
    assert!(
        case.conn()
            .execute(
                "INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('nope', '/y', 't')",
                [],
            )
            .is_err()
    );
}

#[test]
fn upgrading_a_v2_case_keeps_collections_and_adds_ual_tables() {
    use sparrow_core::db::migrations::MIGRATIONS;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.duckdb");
    {
        let conn = duckdb::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL,
             applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
        )
        .unwrap();
        for m in &MIGRATIONS[..2] {
            conn.execute_batch(m.sql).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                duckdb::params![m.version as i64, m.name],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO collections (tool, root_path, sparrow_version) VALUES ('hawk', '/evidence/Hawk_X', '0.1.0')",
            [],
        )
        .unwrap();
    }
    let (from, to) = Case::upgrade(&path).unwrap();
    assert_eq!((from, to), (2, latest_version()));
    let case = Case::open_read_only(&path).unwrap();
    let tool: String = case
        .conn()
        .query_row("SELECT CAST(tool AS VARCHAR) FROM collections", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(tool, "hawk");
    let comment: Option<String> = case
        .conn()
        .query_row(
            "SELECT comment FROM duckdb_columns() WHERE table_name = 'collections' AND column_name = 'tool'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(comment.unwrap().contains("portal_export"));
    assert!(tables(&case).contains(&"ual_events".to_string()));
    assert!(tables(&case).contains(&"users".to_string()));
}

#[test]
fn state_table_specs_match_the_schema() {
    let case = Case::in_memory().unwrap();
    assert_eq!(case.schema_version().unwrap(), 4);
    for spec in ALL {
        for common in [
            "record_key",
            "collection_id",
            "collected_at",
            "raw",
            "column_collections",
        ] {
            assert!(
                data_type(&case, spec.table, common).is_some(),
                "{}.{common} missing",
                spec.table
            );
        }
        for c in spec.columns {
            let actual = data_type(&case, spec.table, c.name)
                .unwrap_or_else(|| panic!("{}.{} missing", spec.table, c.name));
            let expected = match c.sql_type {
                "TIMESTAMPTZ" => "TIMESTAMP WITH TIME ZONE".to_string(),
                t if t.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_') => {
                    assert!(
                        actual.starts_with("ENUM("),
                        "{}.{}: {actual}",
                        spec.table,
                        c.name
                    );
                    continue;
                }
                t => t.to_string(),
            };
            assert_eq!(actual, expected, "{}.{}", spec.table, c.name);
        }
    }
    assert!(ALL.iter().any(|s| s.mode == LoadMode::InsertOnly));
}

#[test]
fn state_tables_do_not_constrain_record_key() {
    let case = Case::in_memory().unwrap();
    case.conn()
        .execute_batch(
            "INSERT INTO users (record_key, collection_id) VALUES ('k', 1);
             INSERT INTO users (record_key, collection_id) VALUES ('k', 1);",
        )
        .unwrap();
    let bad = case.conn().execute(
        "INSERT INTO role_assignments (record_key, collection_id, source) VALUES ('x', 1, 'nope')",
        [],
    );
    assert!(bad.is_err(), "role_source enum must reject unknown values");
}

#[test]
fn ual_events_reject_a_second_row_with_the_same_record_id() {
    let case = Case::in_memory().unwrap();
    let insert = "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision,
                  data_completeness, synthetic_id, audit_data)
                  VALUES ('a1111111-1111-4111-8111-111111111111', 1, '2026-09-01 10:00:00+00', true, 'second',
                  'full', false, '{}')";
    case.conn().execute(insert, []).unwrap();
    assert!(case.conn().execute(insert, []).is_err());
}
