use sparrow_core::db::VerifiedOpen;
use sparrow_core::db::migrations::{MIGRATIONS, latest_version, migrate};
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
            "account_rollup",
            "admin_audit_events",
            "annotations",
            "app_credentials",
            "applications",
            "audit_config",
            "audit_trail",
            "azure_activity",
            "ca_policies",
            "capabilities",
            "case_indicators",
            "case_meta",
            "cloud_services",
            "collection_log",
            "collections",
            "collector_flags",
            "collector_runs",
            "detection_runs",
            "devices",
            "directory_audits",
            "email_artifacts",
            "evidence_availability",
            "file_events",
            "finding_evidence",
            "finding_facts",
            "findings",
            "group_members",
            "groups",
            "identities",
            "identity_aliases",
            "imported_proposals",
            "inbox_rules",
            "ip_intel",
            "licenses",
            "mail_items_accessed",
            "mailbox_audit_legacy",
            "mailbox_permissions",
            "mailboxes",
            "message_trace",
            "mfa_registration",
            "mobile_devices",
            "oauth_grants",
            "operation_catalog",
            "parse_errors",
            "record_sources",
            "remote_domains",
            "risk_detections",
            "risky_users",
            "role_assignments",
            "schema_migrations",
            "search_queries",
            "secure_score",
            "security_alerts",
            "sharing_events",
            "signins",
            "source_files",
            "spray_sources",
            "tenant",
            "tenant_capabilities",
            "tenant_domain_overrides",
            "tenant_domains",
            "tenant_settings",
            "timeline_entries",
            "timeline_entry_evidence",
            "transport_rules",
            "ual_events",
            "user_licenses",
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

/// A case file at schema v20 (before migration 21), built migration by migration; the connection stays open for the
/// caller's rows.
fn v20_conn(path: &std::path::Path) -> duckdb::Connection {
    let conn = duckdb::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL,
         applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
    )
    .unwrap();
    for m in MIGRATIONS.iter().filter(|m| m.version <= 20) {
        conn.execute_batch(m.sql).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
            duckdb::params![m.version as i64, m.name],
        )
        .unwrap();
    }
    conn
}

/// `n` audited agent decisions on `conn`.
fn audited(conn: &duckdb::Connection, n: usize) {
    for i in 0..n {
        conn.execute_batch("BEGIN TRANSACTION").unwrap();
        sparrow_core::case::audit::append(
            conn,
            "agent:t",
            None,
            "test",
            "finding",
            &format!("f{i}"),
            None,
            Some(&serde_json::json!({ "i": i })),
            None,
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();
    }
}

#[test]
fn inspect_reads_schema_and_chain_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = |p: &std::path::Path| std::fs::read(p).unwrap();

    // Current and intact.
    let current = dir.path().join("current.duckdb");
    {
        let case = Case::create_or_open(&current).unwrap();
        audited(case.conn(), 2);
        case.conn().execute_batch("CHECKPOINT").unwrap();
    }
    let before = bytes(&current);
    let i = Case::inspect(&current).unwrap();
    assert_eq!(
        (i.schema_version, i.latest),
        (latest_version(), latest_version())
    );
    let a = i.audit.expect("a current case has an audit trail");
    assert!(a.ok);
    assert_eq!(a.entries, 2);
    assert!(bytes(&current) == before, "the file changed");

    // Current with a broken chain.
    {
        let case = Case::create_or_open(&current).unwrap();
        case.conn()
            .execute("UPDATE audit_trail SET reason = 'x' WHERE seq = 2", [])
            .unwrap();
        case.conn().execute_batch("CHECKPOINT").unwrap();
    }
    let before = bytes(&current);
    let a = Case::inspect(&current).unwrap().audit.unwrap();
    assert!(!a.ok);
    assert_eq!(a.first_bad_seq, Some(2));
    assert!(bytes(&current) == before, "the file changed");

    // Older schema (v20), intact, then broken: reported, never migrated.
    let old = dir.path().join("v20.duckdb");
    {
        let conn = v20_conn(&old);
        audited(&conn, 3);
        conn.execute_batch("CHECKPOINT").unwrap();
    }
    let before = bytes(&old);
    let i = Case::inspect(&old).unwrap();
    assert_eq!((i.schema_version, i.latest), (20, latest_version()));
    assert!(i.audit.unwrap().ok);
    assert!(bytes(&old) == before, "the file changed");
    {
        let conn = duckdb::Connection::open(&old).unwrap();
        conn.execute("UPDATE audit_trail SET actor = 'x' WHERE seq = 1", [])
            .unwrap();
        conn.execute_batch("CHECKPOINT").unwrap();
    }
    let before = bytes(&old);
    let a = Case::inspect(&old).unwrap().audit.unwrap();
    assert_eq!((a.ok, a.first_bad_seq), (false, Some(1)));
    assert!(bytes(&old) == before, "the file changed");
    assert!(matches!(
        Case::open_read_only(&old),
        Err(Error::SchemaOutdated { db: 20, .. })
    ));

    // Before the audit trail (v15): no chain to report.
    let pre = dir.path().join("v15.duckdb");
    {
        let conn = duckdb::Connection::open(&pre).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL,
             applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
        )
        .unwrap();
        for m in MIGRATIONS.iter().filter(|m| m.version <= 15) {
            conn.execute_batch(m.sql).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                duckdb::params![m.version as i64, m.name],
            )
            .unwrap();
        }
    }
    let i = Case::inspect(&pre).unwrap();
    assert_eq!(i.schema_version, 15);
    assert!(i.audit.is_none());

    // Missing file; a file this process holds as writer.
    assert!(matches!(
        Case::inspect(&dir.path().join("nope.duckdb")),
        Err(Error::NotFound(_))
    ));
    assert!(!dir.path().join("nope.duckdb").exists());
    let held = Case::create_or_open(&current).unwrap();
    assert!(matches!(Case::inspect(&current), Err(Error::WriterBusy(_))));
    drop(held);
}

fn verdict(v: &VerifiedOpen) -> &'static str {
    match v {
        VerifiedOpen::Writable(_) => "writable",
        VerifiedOpen::BrokenChain(_) => "broken_chain",
        VerifiedOpen::NeedsAcknowledge { .. } => "needs_acknowledge",
        VerifiedOpen::NeedsUpgrade { .. } => "needs_upgrade",
    }
}

/// The writer is released: an inspection (which refuses a file this process holds as writer) gets through.
fn released(path: &std::path::Path) -> bool {
    Case::inspect(path).is_ok()
}

#[test]
fn open_verified_decides_on_the_writer_before_migrating() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = |p: &std::path::Path| std::fs::read(p).unwrap();
    let latest = latest_version();

    // v20, broken: refused even with the upgrade allowed; nothing written, writer released.
    let broken = dir.path().join("v20-broken.duckdb");
    {
        let conn = v20_conn(&broken);
        audited(&conn, 2);
        conn.execute("UPDATE audit_trail SET actor = 'x' WHERE seq = 1", [])
            .unwrap();
        conn.execute_batch("CHECKPOINT").unwrap();
    }
    let before = bytes(&broken);
    for allow_upgrade in [true, false] {
        let v = Case::open_verified(&broken, allow_upgrade).unwrap();
        match &v {
            VerifiedOpen::NeedsAcknowledge {
                schema_version,
                first_bad_seq,
                ..
            } => assert_eq!((*schema_version, *first_bad_seq), (20, Some(1))),
            other => panic!("expected needs_acknowledge, got {}", verdict(other)),
        }
        drop(v);
        assert!(bytes(&broken) == before, "allow_upgrade={allow_upgrade}");
        assert!(released(&broken));
    }

    // v20, intact: needs the upgrade decision; with it, migrated and verified on the same writer.
    let intact = dir.path().join("v20.duckdb");
    {
        let conn = v20_conn(&intact);
        audited(&conn, 2);
        conn.execute_batch("CHECKPOINT").unwrap();
    }
    let before = bytes(&intact);
    let v = Case::open_verified(&intact, false).unwrap();
    match &v {
        VerifiedOpen::NeedsUpgrade {
            schema_version,
            latest: l,
        } => assert_eq!((*schema_version, *l), (20, latest)),
        other => panic!("expected needs_upgrade, got {}", verdict(other)),
    }
    drop(v);
    assert!(bytes(&intact) == before, "the file changed");
    assert!(released(&intact));
    match Case::open_verified(&intact, true).unwrap() {
        VerifiedOpen::Writable(case) => {
            assert_eq!(case.schema_version().unwrap(), latest);
            assert!(!case.is_read_only());
            let r = sparrow_core::case::audit::verify(case.conn()).unwrap();
            assert!(r.ok);
            assert_eq!(
                r.entries, 2,
                "a v20 case already has its trail; no upgrade entry"
            );
        }
        other => panic!("expected writable, got {}", verdict(&other)),
    }
    assert!(released(&intact));

    // Current schema: intact → writable; broken → reported, nothing written, writer released.
    let current = dir.path().join("current.duckdb");
    {
        let case = Case::create_or_open(&current).unwrap();
        audited(case.conn(), 2);
    }
    match Case::open_verified(&current, false).unwrap() {
        VerifiedOpen::Writable(case) => assert_eq!(case.schema_version().unwrap(), latest),
        other => panic!("expected writable, got {}", verdict(&other)),
    }
    {
        let case = Case::create_or_open(&current).unwrap();
        case.conn()
            .execute("UPDATE audit_trail SET reason = 'x' WHERE seq = 2", [])
            .unwrap();
        case.conn().execute_batch("CHECKPOINT").unwrap();
    }
    let before = bytes(&current);
    match Case::open_verified(&current, true).unwrap() {
        VerifiedOpen::BrokenChain(r) => assert_eq!((r.ok, r.first_bad_seq), (false, Some(2))),
        other => panic!("expected broken_chain, got {}", verdict(&other)),
    }
    assert!(bytes(&current) == before, "the file changed");
    assert!(released(&current));

    // Missing file: not found, nothing created. A file this process holds: busy.
    let missing = dir.path().join("nope.duckdb");
    assert!(matches!(
        Case::open_verified(&missing, true),
        Err(Error::NotFound(_))
    ));
    assert!(!missing.exists());
    let held = Case::create_or_open(&current).unwrap();
    assert!(matches!(
        Case::open_verified(&current, false),
        Err(Error::WriterBusy(_))
    ));
    drop(held);
}

#[test]
fn upgrading_a_v20_case_keeps_decisions_and_adds_imported_proposals() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v20.duckdb");
    {
        let conn = v20_conn(&path);
        conn.execute_batch(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, created_by, created_at, updated_at, status, decided_by, decided_at, review_state)
             VALUES ('f1', 'fp1', 't1', 'SPW-ID-004', 1, 'x', 'high', 'AiTM', 'rule', now(), now(), 'confirmed',
                     'agent:claude', now(), 'pending_review');
             INSERT INTO annotations (annotation_id, object_type, object_id, text, actor, created_at)
             VALUES ('n1', 'finding', 'f1', 'checked', 'agent:claude', now());",
        )
        .unwrap();
    }
    let (from, to) = Case::upgrade(&path).unwrap();
    assert_eq!((from, to), (20, 21));
    let case = Case::open_read_only(&path).unwrap();
    assert_eq!(case.schema_version().unwrap(), 21);
    let kept: (String, String, String, String) = case
        .conn()
        .query_row(
            "SELECT CAST(f.status AS VARCHAR), f.decided_by, CAST(f.review_state AS VARCHAR), a.text \
             FROM findings f JOIN annotations a ON a.object_id = f.finding_id",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        kept,
        (
            "confirmed".into(),
            "agent:claude".into(),
            "pending_review".into(),
            "checked".into()
        )
    );
    assert!(tables(&case).contains(&"imported_proposals".to_string()));
    let n: i64 = case
        .conn()
        .query_row("SELECT count(*) FROM imported_proposals", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
    let comment: Option<String> = case
        .conn()
        .query_row(
            "SELECT comment FROM duckdb_columns() WHERE table_name = 'findings' AND column_name = 'decided_by'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(comment.unwrap().contains("analyst:<name>"));
}

#[test]
fn describe_lists_views_with_their_kind() {
    let case = Case::in_memory().unwrap();
    let all = sparrow_core::db::describe(&case, Some("tenant_audit_config")).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].kind, "view");
    assert!(all[0].comment.as_deref().is_some_and(|c| !c.is_empty()));
}

#[test]
fn state_table_specs_match_the_schema() {
    let case = Case::in_memory().unwrap();
    assert_eq!(case.schema_version().unwrap(), 21);
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

#[test]
fn event_tables_fill_missing_values() {
    use sparrow_core::db::state_tables::{
        ADMIN_AUDIT_EVENTS, DIRECTORY_AUDITS, MAILBOX_AUDIT_LEGACY, MESSAGE_TRACE, SIGNINS,
    };
    for spec in [
        &SIGNINS,
        &DIRECTORY_AUDITS,
        &MESSAGE_TRACE,
        &MAILBOX_AUDIT_LEGACY,
        &ADMIN_AUDIT_EVENTS,
    ] {
        assert_eq!(spec.mode, LoadMode::FillMissing, "{}", spec.table);
        assert!(
            ALL.iter().any(|s| s.table == spec.table),
            "{} not in ALL",
            spec.table
        );
    }
    let case = Case::in_memory().unwrap();
    assert_eq!(
        data_type(&case, "admin_audit_events", "parameters").as_deref(),
        Some("MAP(VARCHAR, VARCHAR)")
    );
    let bad = case.conn().execute(
        "INSERT INTO signins (record_key, collection_id, event_type) VALUES ('x', 1, 'bogus')",
        [],
    );
    assert!(bad.is_err(), "signin_event_type must reject unknown values");
}

#[test]
fn provenance_comments_describe_xlsx_rows() {
    let case = Case::in_memory().unwrap();
    let c: String = case
        .conn()
        .query_row(
            "SELECT comment FROM duckdb_columns() WHERE table_name = 'record_sources' AND column_name = 'raw_sha256'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(c.contains("XLSX"), "{c}");
}

#[test]
fn phase3_columns_exist() {
    let case = Case::in_memory().unwrap();
    for (table, column, ty) in [
        ("collector_runs", "rel_dir", "VARCHAR"),
        ("collector_runs", "run_stamp", "TIMESTAMP WITH TIME ZONE"),
        ("collector_runs", "files", "INTEGER"),
        ("collector_runs", "empty_files", "INTEGER"),
        ("collector_runs", "bytes", "BIGINT"),
        ("mailboxes", "audit_bypass_enabled", "BOOLEAN"),
        ("mailboxes", "default_audit_set", "VARCHAR[]"),
        ("mailboxes", "effective_audit_state", "VARCHAR"),
        ("mail_items_accessed", "item_key", "VARCHAR"),
        (
            "mail_items_accessed",
            "event_time",
            "TIMESTAMP WITH TIME ZONE",
        ),
        ("mail_items_accessed", "user_upn", "VARCHAR"),
        ("mail_items_accessed", "client_ip", "VARCHAR"),
        ("mail_items_accessed", "session_id", "VARCHAR"),
        ("mail_items_accessed", "time_tz_assumed", "BOOLEAN"),
    ] {
        assert_eq!(
            data_type(&case, table, column).as_deref(),
            Some(ty),
            "{table}.{column}"
        );
    }
}

#[test]
fn mailbox_permissions_spec_is_latest_wins() {
    use sparrow_core::db::state_tables::MAILBOX_PERMISSIONS;
    assert_eq!(MAILBOX_PERMISSIONS.mode, LoadMode::LatestWins);
    assert!(ALL.iter().any(|s| s.table == "mailbox_permissions"));
    let case = Case::in_memory().unwrap();
    // The enum rejects unknown rights.
    assert!(
        case.conn()
            .execute_batch(
                "INSERT INTO mailbox_permissions (record_key, collection_id, permission) VALUES ('k', 1, 'owner')"
            )
            .is_err()
    );
}

#[test]
fn signin_comments_describe_extractor_suite_sources() {
    let case = Case::in_memory().unwrap();
    let comment = |col: &str| -> String {
        case.conn()
            .query_row(
                "SELECT comment FROM duckdb_columns() WHERE table_name = 'signins' AND column_name = ?",
                [col],
                |r| r.get(0),
            )
            .unwrap()
    };
    let et = comment("event_type");
    for part in [
        "signInEventTypes",
        "isInteractive",
        "portal export file name",
        "managed_identity",
    ] {
        assert!(et.contains(part), "{et}");
    }
    let mfa = comment("mfa_detail");
    assert!(
        mfa.contains("Portal") && mfa.contains("mfaDetail.authDetail"),
        "{mfa}"
    );
    let am = comment("auth_methods");
    assert!(
        am.contains("authenticationDetails") && am.contains("mfaDetail.authMethod"),
        "{am}"
    );
}

#[test]
fn every_loaded_table_has_a_tz_assumed_column() {
    let case = Case::in_memory().unwrap();
    for spec in ALL {
        assert_eq!(
            data_type(&case, spec.table, "tz_assumed").as_deref(),
            Some("JSON"),
            "{}",
            spec.table
        );
    }
}

/// A case created by schema 6 (one merged org row, one row per transport rule / remote domain)
/// gains per-collection keys, and its sightings follow the rows so verify keeps working.
#[test]
fn migration_7_keys_org_state_transport_rules_and_remote_domains_by_collection() {
    let conn = duckdb::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL,
             applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
    )
    .unwrap();
    for m in MIGRATIONS.iter().filter(|m| m.version <= 6) {
        conn.execute_batch(m.sql).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
            duckdb::params![m.version, m.name],
        )
        .unwrap();
    }
    conn.execute_batch(
        "INSERT INTO collections (collection_id, tool, root_path, sparrow_version) VALUES (3, 'hawk', '/c', 't');
         INSERT INTO source_files (file_id, collection_id, rel_path, size_bytes, sha256, status)
             VALUES (9, 3, 'Tenant/OrgConfig.txt', 1, 'h', 'parsed');
         INSERT INTO audit_config (record_key, collection_id, audit_disabled) VALUES ('organization', 3, true);
         INSERT INTO tenant_settings (record_key, collection_id, source, name)
             VALUES ('organization_config|auditdisabled', 3, 'organization_config', 'AuditDisabled');
         INSERT INTO transport_rules (record_key, collection_id, name) VALUES ('external redirect', 3, 'External redirect');
         INSERT INTO remote_domains (record_key, collection_id, domain_name) VALUES ('*', 3, '*');
         INSERT INTO record_sources VALUES
             ('audit_config', 'organization', 9, 0, 2, 2, 0, 1, 'h'),
             ('tenant_settings', 'organization_config|auditdisabled', 9, 0, 2, 2, 0, 1, 'h'),
             ('transport_rules', 'external redirect', 9, 0, 2, 2, 0, 1, 'h'),
             ('remote_domains', '*', 9, 0, 2, 2, 0, 1, 'h');",
    )
    .unwrap();
    migrate(&conn).unwrap();
    let keys: Vec<String> = conn
        .prepare(
            "SELECT record_key FROM audit_config UNION ALL SELECT record_key FROM tenant_settings
             UNION ALL SELECT record_key FROM transport_rules UNION ALL SELECT record_key FROM remote_domains
             UNION ALL SELECT table_name || '=' || record_key FROM record_sources ORDER BY 1",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        keys,
        vec![
            "3|*",
            "3|external redirect",
            "3|organization_config|auditdisabled",
            "audit_config=organization|3",
            "organization|3",
            "remote_domains=3|*",
            "tenant_settings=3|organization_config|auditdisabled",
            "transport_rules=3|external redirect",
        ]
    );
}

/// The admin_audit_events record_key COMMENT's documented text is what is hashed.
#[test]
fn admin_audit_key_follows_the_documented_text() {
    use sha2::{Digest, Sha256};
    let case = Case::in_memory().unwrap();
    let c: String = case
        .conn()
        .query_row(
            "SELECT comment FROM duckdb_columns() WHERE table_name = 'admin_audit_events' AND column_name = 'record_key'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        c.contains("\"admin_audit\\n<run>\\n<cmdlet>\\n<object>\\n<caller>\""),
        "{c}"
    );
    let v = serde_json::json!({
        "CmdletName": "New-InboxRule",
        "RunDate": "2026-09-04T13:05:09.250+02:00",
        "ObjectModified": "EURPR01/Tenants/contoso/ann@contoso.example\\Sync",
        "Caller": "Admin@Contoso.example",
    });
    let rec = sparrow_core::normalize::fields::Rec::new(v.as_object().unwrap(), false);
    let key = sparrow_core::parsers::admin_audit::admin_audit_key(&rec, None).unwrap();
    let text = "admin_audit\n2026-09-04T11:05:09Z\nnew-inboxrule\nsync\nadmin@contoso.example";
    assert_eq!(key, hex::encode(Sha256::digest(text.as_bytes())));
}
