//! The locked-down `query` connection (Codex reviews `case/query.rs` with this list).

use sparrow_core::Case;
use sparrow_core::case::query;
use std::path::PathBuf;

/// A case file with 5,000 ip_intel rows and one finding.
fn case_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("c.duckdb");
    let c = Case::create_or_open(&p).unwrap();
    c.conn()
        .execute_batch(
            "INSERT INTO ip_intel (ip, country_iso, is_hosting, is_microsoft, is_private)
                 SELECT '198.51.100.' || i, 'US', false, false, false FROM range(5000) t(i);
             INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity,
                                   title, created_by, created_at, updated_at)
             VALUES ('f1', 'fp1', 't1', 'R', 1, 'x', 'high', 'AiTM', 'rule', now(), now());",
        )
        .unwrap();
    drop(c);
    (dir, p)
}

#[test]
fn a_select_runs_and_reports_columns_and_rows() {
    let (_d, p) = case_file();
    let r = query::run(&p, "SELECT count(*) AS n, 'x' AS s FROM ip_intel", 10).unwrap();
    assert_eq!(r.columns, ["n", "s"]);
    assert_eq!(
        r.rows,
        vec![vec![serde_json::json!(5000), serde_json::json!("x")]]
    );
    assert!(!r.truncated);
    let r = query::run(
        &p,
        "-- the top finding\nWITH f AS (SELECT * FROM findings) SELECT finding_id, severity, created_at IS NOT NULL AS has_t FROM f;",
        10,
    )
    .unwrap();
    assert_eq!(
        r.rows[0],
        vec![
            serde_json::json!("f1"),
            serde_json::json!("high"),
            serde_json::json!(true)
        ]
    );
}

#[test]
fn a_large_select_is_truncated_at_the_limit() {
    let (_d, p) = case_file();
    let r = query::run(&p, "SELECT ip FROM ip_intel ORDER BY ip", 10).unwrap();
    assert_eq!(r.rows.len(), 10);
    assert!(r.truncated);
    let r = query::run(&p, "SELECT ip FROM ip_intel", 5000).unwrap();
    assert_eq!((r.rows.len(), r.truncated), (5000, false));
}

#[test]
fn query_is_read_only_and_locked_down() {
    let (d, p) = case_file();
    let probe = d.path().join("probe");
    let pr = probe.display().to_string();
    let refused = [
        "INSERT INTO case_meta VALUES ('x','y')".to_string(),
        "DELETE FROM findings".into(),
        "UPDATE findings SET status = 'confirmed'".into(),
        "DROP TABLE findings".into(),
        "CREATE TABLE x AS SELECT 1".into(),
        "SELECT * FROM read_csv('/etc/passwd')".into(),
        "SELECT * FROM read_text('/etc/passwd')".into(),
        "SELECT * FROM glob('/etc/*')".into(),
        "SELECT getenv('HOME')".into(),
        "SELECT * FROM query('DELETE FROM findings')".into(),
        "SELECT * FROM '/etc/passwd'".into(),
        "SELECT * FROM read_parquet('/etc/passwd')".into(),
        format!("COPY findings TO '{pr}.csv'"),
        format!("COPY (SELECT 1) TO '{pr}.csv'"),
        format!("ATTACH '{pr}.duckdb' AS y"),
        "DETACH c".into(),
        "SET enable_external_access = true".into(),
        "RESET lock_configuration".into(),
        "INSTALL httpfs".into(),
        "LOAD httpfs".into(),
        "PRAGMA database_list".into(),
        "CALL pragma_version()".into(),
        format!("EXPORT DATABASE '{pr}-export'"),
        "SELECT 1; DELETE FROM findings".into(),
        "SELECT 1; SELECT 2".into(),
        "SELECT 1 /* ; */ ; DROP TABLE findings".into(),
        "SELECT 1 -- hidden\n; DELETE FROM findings".into(),
        "/* SELECT */ DELETE FROM findings".into(),
        "BEGIN TRANSACTION".into(),
        "CHECKPOINT".into(),
        String::new(),
        "   ".into(),
    ];
    for sql in &refused {
        let r = query::run(&p, sql, 10);
        assert!(r.is_err(), "{sql:?} must be refused, got {r:?}");
    }
    // No file was written next to the probe path.
    let written: Vec<_> = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("probe"))
        .collect();
    assert!(written.is_empty(), "{written:?}");
    // Nothing changed.
    let c = Case::open_read_only(&p).unwrap();
    let n: i64 = c
        .conn()
        .query_row("SELECT count(*) FROM findings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
    let n: i64 = c
        .conn()
        .query_row("SELECT count(*) FROM case_meta WHERE key = 'x'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn query_never_opens_the_case_for_writing() {
    // A writer in another handle of this process would conflict; the query instance attaches READ_ONLY, so the case
    // file is never modified: its bytes are identical before and after.
    let (_d, p) = case_file();
    let before = std::fs::read(&p).unwrap();
    query::run(&p, "SELECT count(*) FROM ip_intel", 1).unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), before);
    assert!(!p.with_extension("duckdb.wal").exists());
}

#[test]
fn the_case_meta_keys_are_visible() {
    let (_d, p) = case_file();
    let r = query::run(&p, "SELECT key FROM case_meta ORDER BY key", 10).unwrap();
    assert!(r.rows.iter().any(|row| row[0] == "case_id"), "{r:?}");
}
