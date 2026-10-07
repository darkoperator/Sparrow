//! The locked-down `query` connection (Codex reviews `case/query.rs` with this list).

use chrono::{TimeZone, Utc};
use sparrow_core::case::actor::Actor;
use sparrow_core::case::query;
use sparrow_core::case::write::{FindingStatus, set_finding_status};
use sparrow_core::data::DataDirs;
use sparrow_core::export::report_md::{self, ReportOpts};
use sparrow_core::export::timeline_csv::{self, CsvOpts, Scope};
use sparrow_core::export::workbook_xlsx;
use sparrow_core::{Case, Error};
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

#[test]
fn run_on_refuses_unlocked_case() {
    let c = Case::in_memory().unwrap();
    assert!(!c.is_locked_down().unwrap());
    let e = query::run_on(&c, "SELECT 1", 10).unwrap_err();
    assert!(matches!(&e, Error::Invalid(m) if m.contains("lock")), "{e}");
    let e = query::schema_on(&c, None).unwrap_err();
    assert!(matches!(&e, Error::Invalid(m) if m.contains("lock")), "{e}");
}

#[test]
fn run_on_matches_run_and_cannot_write() {
    let (d, p) = case_file();
    let expected = query::run(&p, "SELECT finding_id FROM findings ORDER BY 1", 100).unwrap();
    assert_eq!(expected.rows.len(), 1);
    let c = Case::create_or_open(&p).unwrap();
    c.lock_down().unwrap();
    assert!(c.is_locked_down().unwrap());
    let got = query::run_on(&c, "SELECT finding_id FROM findings ORDER BY 1", 100).unwrap();
    assert_eq!(got.columns, expected.columns);
    assert_eq!(got.rows, expected.rows);
    let probe = d.path().join("probe");
    let pr = probe.display().to_string();
    for bad in [
        "DELETE FROM findings".to_string(),
        "SELECT 1; DELETE FROM findings".into(),
        "SELECT * FROM read_csv('/etc/hosts')".into(),
        "SELECT getenv('HOME')".into(),
        format!("COPY findings TO '{pr}.csv'"),
        format!("ATTACH '{pr}.duckdb' AS x"),
        "SET enable_external_access = true".into(),
        "BEGIN TRANSACTION".into(),
        "CHECKPOINT".into(),
        String::new(),
    ] {
        assert!(query::run_on(&c, &bad, 10).is_err(), "{bad}");
    }
    // Nothing changed and the connection is not left in a transaction.
    let n = query::run_on(&c, "SELECT count(*) FROM findings", 10).unwrap();
    assert_eq!(n.rows, vec![vec![serde_json::json!(1)]]);
    c.conn()
        .execute_batch("BEGIN TRANSACTION; ROLLBACK")
        .unwrap();
    let t = query::schema_on(&c, Some("findings")).unwrap();
    assert_eq!(t.len(), 1);
    assert!(query::schema_on(&c, None).unwrap().len() > 1);
    // Truncation works the same as `run`.
    let r = query::run_on(&c, "SELECT ip FROM ip_intel ORDER BY ip", 10).unwrap();
    assert_eq!((r.rows.len(), r.truncated), (10, true));
    assert!(!probe.with_extension("csv").exists());
}

#[test]
fn run_on_refuses_inside_an_open_transaction_and_leaves_it_alone() {
    let (_d, p) = case_file();
    let c = Case::create_or_open(&p).unwrap();
    c.lock_down().unwrap();
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    assert!(query::run_on(&c, "SELECT 1", 10).is_err());
    // The caller's transaction is still open: COMMIT succeeds.
    c.conn().execute_batch("COMMIT").unwrap();
}

#[test]
fn lock_down_cannot_be_undone_and_writes_still_work() {
    // The probe the brief asks for: lock_configuration on the writer instance must not break what a write needs
    // (BEGIN/COMMIT in `in_tx`, the audit append, the checkpoint when the case closes).
    let (_d, p) = case_file();
    let c = Case::create_or_open(&p).unwrap();
    c.lock_down().unwrap();
    for undo in [
        "SET lock_configuration = false",
        "SET enable_external_access = true",
    ] {
        assert!(c.conn().execute_batch(undo).is_err(), "{undo}");
    }
    let agent = Actor::agent("claude", Some("example")).unwrap();
    let e = set_finding_status(c.conn(), &agent, "f1", FindingStatus::InReview, None).unwrap();
    assert_eq!(e.actor, "agent:claude");
    c.conn().execute_batch("CHECKPOINT").unwrap();
    drop(c);
    let c = Case::create_or_open(&p).unwrap();
    let status: String = c
        .conn()
        .query_row("SELECT CAST(status AS VARCHAR) FROM findings", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(status, "in_review");
    assert!(sparrow_core::case::audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn locked_case_still_takes_an_agent_decision_and_exports() {
    let (d, p) = case_file();
    let c = Case::create_or_open(&p).unwrap();
    c.lock_down().unwrap();
    let agent = Actor::agent("claude", Some("example")).unwrap();
    set_finding_status(c.conn(), &agent, "f1", FindingStatus::Confirmed, Some("r")).unwrap();
    let at = Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap();
    let mut md = Vec::new();
    report_md::write(
        c.conn(),
        &mut md,
        &ReportOpts {
            reviewed_only: false,
            generated_at: at,
            dirs: DataDirs::default(),
        },
    )
    .unwrap();
    let md = String::from_utf8(md).unwrap();
    assert!(md.contains("AiTM"), "{md}");
    let xlsx = d.path().join("case.xlsx");
    workbook_xlsx::write(c.conn(), &xlsx, at, &DataDirs::default()).unwrap();
    assert!(std::fs::metadata(&xlsx).unwrap().len() > 0);
    let mut csv = Vec::new();
    timeline_csv::write(
        c.conn(),
        &mut csv,
        &CsvOpts {
            scope: Scope::All,
            from: None,
            to: None,
            user: None,
            generated_at: at,
        },
    )
    .unwrap();
    assert!(!csv.is_empty());
    // The audit chain is intact after the locked-down write.
    assert!(sparrow_core::case::audit::verify(c.conn()).unwrap().ok);
}

#[test]
fn run_on_leaves_the_case_unchanged_even_for_a_side_effecting_select_shape() {
    // Probe what gets past the one-SELECT check: a table function that runs a statement. Whatever DuckDB accepts here
    // must be rolled back (or refused); the case must not change either way.
    let (_d, p) = case_file();
    let c = Case::create_or_open(&p).unwrap();
    c.lock_down().unwrap();
    let before = |c: &Case| -> String {
        c.conn()
            .query_row(
                "SELECT CAST(severity AS VARCHAR) || (SELECT count(*) FROM ip_intel) FROM findings",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    let b = before(&c);
    let mut ran = 0;
    for sql in [
        "SELECT * FROM query('UPDATE findings SET severity = ''low'' RETURNING finding_id')",
        "SELECT * FROM query('DELETE FROM ip_intel RETURNING ip')",
        "WITH d AS (DELETE FROM ip_intel RETURNING ip) SELECT count(*) FROM d",
    ] {
        if query::run_on(&c, sql, 10).is_ok() {
            ran += 1;
        }
        assert_eq!(before(&c), b, "{sql}");
    }
    eprintln!("side-effecting SELECT shapes that ran: {ran}");
    // A query that fails at execution after BEGIN leaves no transaction behind; a write then works.
    assert!(query::run_on(&c, "SELECT CAST('x' AS INTEGER)", 10).is_err());
    let agent = Actor::agent("claude", Some("example")).unwrap();
    set_finding_status(c.conn(), &agent, "f1", FindingStatus::InReview, None).unwrap();
}
