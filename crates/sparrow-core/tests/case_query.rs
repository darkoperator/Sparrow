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
    let e = query::run_on(&c, "SELECT 1", 10, 0).unwrap_err();
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
    let got = query::run_on(&c, "SELECT finding_id FROM findings ORDER BY 1", 100, 0).unwrap();
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
        assert!(query::run_on(&c, &bad, 10, 0).is_err(), "{bad}");
    }
    // Nothing changed and the connection is not left in a transaction.
    let n = query::run_on(&c, "SELECT count(*) FROM findings", 10, 0).unwrap();
    assert_eq!(n.rows, vec![vec![serde_json::json!(1)]]);
    c.conn()
        .execute_batch("BEGIN TRANSACTION; ROLLBACK")
        .unwrap();
    let t = query::schema_on(&c, Some("findings")).unwrap();
    assert_eq!(t.len(), 1);
    assert!(query::schema_on(&c, None).unwrap().len() > 1);
    // Truncation works the same as `run`.
    let r = query::run_on(&c, "SELECT ip FROM ip_intel ORDER BY ip", 10, 0).unwrap();
    assert_eq!((r.rows.len(), r.truncated), (10, true));
    assert!(!probe.with_extension("csv").exists());
}

#[test]
fn run_on_refuses_inside_an_open_transaction_and_leaves_it_alone() {
    let (_d, p) = case_file();
    let c = Case::create_or_open(&p).unwrap();
    c.lock_down().unwrap();
    c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
    assert!(query::run_on(&c, "SELECT 1", 10, 0).is_err());
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
        if query::run_on(&c, sql, 10, 0).is_ok() {
            ran += 1;
        }
        assert_eq!(before(&c), b, "{sql}");
    }
    eprintln!("side-effecting SELECT shapes that ran: {ran}");
    // A query that fails at execution after BEGIN leaves no transaction behind; a write then works.
    assert!(query::run_on(&c, "SELECT CAST('x' AS INTEGER)", 10, 0).is_err());
    let agent = Actor::agent("claude", Some("example")).unwrap();
    set_finding_status(c.conn(), &agent, "f1", FindingStatus::InReview, None).unwrap();
}

#[test]
fn locked_case_still_takes_review_app_writes_and_exports() {
    use sparrow_core::case::actor::Reviewer;
    use sparrow_core::case::share;
    let (_d, p) = case_file();
    let c = Case::create_or_open(&p).unwrap();
    c.lock_down().unwrap();
    let carlos = Reviewer::analyst("carlos").unwrap();
    set_finding_status(
        c.conn(),
        &carlos.as_actor(),
        "f1",
        FindingStatus::Confirmed,
        Some("r"),
    )
    .unwrap();
    let (bytes, _) = share::to_bytes(&share::export(c.conn(), &carlos).unwrap()).unwrap();
    // Importing its own bundle: every item agrees, and the import is audited on the locked case.
    let s = share::import(c.conn(), &carlos, &bytes).unwrap();
    assert_eq!((s.new, s.conflicts, s.missing), (0, 0, 0));
    assert!(s.agrees >= 1);
    assert!(sparrow_core::case::audit::verify(c.conn()).unwrap().ok);
}

// ---- SQL screen: check, paging, CSV export ----

use query::{Check, CheckKind};

fn locked_mem() -> Case {
    let c = Case::in_memory().unwrap();
    c.lock_down().unwrap();
    c
}

/// The UTF-16 offset of the LAST `needle` in `s`, and of its end.
fn span16(s: &str, needle: &str) -> (usize, usize) {
    let b = s.rfind(needle).unwrap();
    let from = s[..b].encode_utf16().count();
    (from, from + needle.encode_utf16().count())
}

fn failed(c: &Check) -> &query::CheckError {
    assert!(!c.ok, "{c:?}");
    c.error.as_ref().unwrap()
}

#[test]
fn check_marks_syntax_errors_in_utf16_offsets() {
    let c = locked_mem();
    for (sql, token) in [
        ("SELECT a,\n  FROM WHERE x", "WHERE"),
        ("SELECT 'é😀日本' AS x,\r\n 1 FROM FROM", "FROM"),
        ("-- note é\nSELECT 1 +\n\n FROM t", "FROM"),
    ] {
        let got = query::check_on(&c, sql).unwrap();
        let e = failed(&got);
        assert_eq!(e.kind, CheckKind::Syntax, "{sql:?}: {e:?}");
        assert_eq!(
            (e.from, e.to),
            {
                let (f, t) = span16(sql, token);
                (Some(f), Some(t))
            },
            "{sql:?}: {e:?}"
        );
        assert!(e.message.contains("syntax error"), "{e:?}");
    }
    // At the end of the text: a zero-width mark at the end, never past it.
    let sql = "SELECT (1";
    let e = query::check_on(&c, sql).unwrap().error.unwrap();
    let n = sql.encode_utf16().count();
    assert_eq!(
        (e.kind, e.from, e.to),
        (CheckKind::Syntax, Some(n), Some(n)),
        "{e:?}"
    );
}

#[test]
fn check_marks_binder_and_catalog_errors_in_the_users_text() {
    let c = locked_mem();
    // Multi-line, non-ASCII (wide and astral) before the error, a tab, and a line long enough that DuckDB truncates
    // its excerpt: the caret refers to the user's text, not a wrapped query.
    let long = "x".repeat(150);
    let cases: Vec<(String, &str, CheckKind, &str)> = vec![
        (
            "SELECT 'é😀日本',\n  finding_idd\nFROM findings".into(),
            "finding_idd",
            CheckKind::Binder,
            "finding_id",
        ),
        (
            "SELECT\tfinding_idd FROM findings".into(),
            "finding_idd",
            CheckKind::Binder,
            "finding_id",
        ),
        (
            format!("SELECT '{long}', 'ü', finding_idd, '{long}' FROM findings"),
            "finding_idd",
            CheckKind::Binder,
            "finding_id",
        ),
        (
            "SELECT f.x, 'ñ'\nFROM findings f\nWHERE zz.severity = 'high'".into(),
            "zz.severity",
            CheckKind::Binder,
            "f",
        ),
        (
            "SELECT *\n  -- é😀\n  FROM  findngs".into(),
            "findngs",
            CheckKind::Catalog,
            "findings",
        ),
        (
            "SELECT \"😀\" FROM findings".into(),
            "\"😀\"",
            CheckKind::Binder,
            "",
        ),
    ];
    for (sql, token, kind, suggestion) in &cases {
        let got = query::check_on(&c, sql).unwrap();
        let e = failed(&got);
        assert_eq!(e.kind, *kind, "{sql:?}: {e:?}");
        let (from, to) = span16(sql, token);
        let want_to = if token.starts_with("zz") {
            from + 2
        } else {
            to
        };
        assert_eq!(
            (e.from, e.to),
            (Some(from), Some(want_to)),
            "{sql:?}: {e:?}"
        );
        if !suggestion.is_empty() {
            assert!(
                e.suggestions.iter().any(|s| s == suggestion),
                "{sql:?}: {e:?}"
            );
        }
        assert!(!e.message.contains("LINE "), "{e:?}");
        assert!(!e.message.is_empty());
    }
    let ok = query::check_on(&c, "SELECT finding_id,\n severity FROM findings -- é\n;").unwrap();
    assert_eq!(
        ok,
        Check {
            ok: true,
            error: None
        }
    );
}

#[test]
fn check_refuses_non_selects_as_syntax_and_needs_a_lock() {
    let c = locked_mem();
    for sql in [
        "DELETE FROM findings",
        "SELECT 1; SELECT 2",
        "",
        "ATTACH 'x' AS y",
    ] {
        let got = query::check_on(&c, sql).unwrap();
        let e = failed(&got);
        assert_eq!(e.kind, CheckKind::Syntax, "{sql:?}: {e:?}");
        assert!(e.message.starts_with("query accepts"), "{e:?}");
    }
    let open = Case::in_memory().unwrap();
    assert!(
        matches!(query::check_on(&open, "SELECT 1"), Err(Error::Invalid(m)) if m.contains("lock"))
    );
}

#[test]
fn check_never_executes() {
    let c = locked_mem();
    // Minutes when executed; binding alone is instant.
    let started = std::time::Instant::now();
    let got = query::check_on(&c, "SELECT sum(hash(a)) FROM range(100000000000) a").unwrap();
    assert!(got.ok, "{got:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // A failing function is only an error when it runs.
    let boom = "SELECT CASE WHEN i = 2 THEN error('boom') ELSE 'x' END AS v FROM range(3) t(i)";
    assert!(query::check_on(&c, boom).unwrap().ok);
    assert!(query::run_on(&c, boom, 10, 0).is_err());
    // The connection is not left in a transaction.
    c.conn()
        .execute_batch("BEGIN TRANSACTION; ROLLBACK")
        .unwrap();
}

#[test]
fn pages_are_slices_of_an_ordered_query() {
    let c = locked_mem();
    let sql = "SELECT i, hash(i) AS h FROM range(30000) t(i) ORDER BY h, i";
    let all = query::run_on(&c, sql, 10_000, 0).unwrap();
    assert_eq!(all.rows.len(), 10_000);
    assert!(all.ordered);
    let mut checked = 0;
    for page in 0..3 {
        let p = query::run_on(&c, sql, 1000, page * 1000).unwrap();
        assert!(p.ordered && p.truncated);
        assert_eq!(
            p.rows[..],
            all.rows[page * 1000..(page + 1) * 1000],
            "page {page}"
        );
        checked += p.rows.len();
    }
    assert_eq!(checked, 3000);
    let last = query::run_on(&c, sql, 1000, 29_500).unwrap();
    assert_eq!((last.rows.len(), last.truncated), (500, false));
    assert!(query::run_on(&c, sql, 10, 40_000).unwrap().rows.is_empty());
    let e = query::run_on(&c, sql, 10, query::MAX_OFFSET + 1).unwrap_err();
    assert!(
        matches!(&e, Error::Invalid(m) if m.contains("offset")),
        "{e}"
    );
}

#[test]
fn ordered_comes_from_the_top_level_select() {
    let c = locked_mem();
    for (sql, want) in [
        ("SELECT 1 AS a ORDER BY a", true),
        ("SELECT 1 AS a UNION ALL SELECT 2 ORDER BY 1", true),
        (
            "WITH x AS (SELECT 1 AS a) SELECT * FROM x ORDER BY ALL LIMIT 5",
            true,
        ),
        ("FROM range(3) t(i) ORDER BY i DESC", true),
        ("SELECT 1 AS a", false),
        ("SELECT * FROM (SELECT 1 AS a ORDER BY a)", false),
        ("SELECT 'ORDER BY' AS t -- ORDER BY t", false),
        ("SELECT a FROM (SELECT 1 AS a) GROUP BY a", false),
    ] {
        assert_eq!(
            query::run_on(&c, sql, 10, 0).unwrap().ordered,
            want,
            "{sql}"
        );
    }
}

fn export(c: &Case, sql: &str, cap: u64) -> (query::Exported, String) {
    let mut out = Vec::new();
    let e = query::export_csv_on(c, sql, &mut out, cap).unwrap();
    (e, String::from_utf8(out).unwrap())
}

#[test]
fn export_writes_every_row_with_the_timeline_cell_rules() {
    let c = locked_mem();
    let sql = "SELECT '=1+1' AS \"=f\", '-x' AS t, -5 AS n, 1.5::DOUBLE AS d, true AS b, NULL AS nul, \
               TIMESTAMP '2026-08-14 10:00:01.5' AS ts, TIMESTAMPTZ '2026-08-14 10:00:00+00' AS tz, \
               DATE '2026-08-14' AS day, ['a', '=b'] AS l, 'a,b \"q\"\nline' AS q, '@x' AS a, 'mid=dle' AS m";
    let (e, text) = export(&c, sql, 10);
    assert_eq!(
        e,
        query::Exported {
            rows: 1,
            capped: false
        }
    );
    let text = text
        .strip_prefix('\u{feff}')
        .expect("a UTF-8 BOM, like the timeline CSV");
    let mut r = csv::Reader::from_reader(text.as_bytes());
    let head: Vec<String> = r.headers().unwrap().iter().map(String::from).collect();
    assert_eq!(
        head,
        [
            "'=f", "t", "n", "d", "b", "nul", "ts", "tz", "day", "l", "q", "a", "m"
        ]
    );
    let rows: Vec<Vec<String>> = r
        .records()
        .map(|x| x.unwrap().iter().map(String::from).collect())
        .collect();
    assert_eq!(
        rows,
        vec![vec![
            "'=1+1",
            "'-x",
            "-5",
            "1.5",
            "true",
            "",
            "2026-08-14T10:00:01.500000Z",
            "2026-08-14T10:00:00.000000Z",
            "2026-08-14",
            "[\"a\",\"=b\"]",
            "a,b \"q\"\nline",
            "'@x",
            "mid=dle",
        ]]
    );
}

#[test]
fn export_caps_and_streams_the_whole_query() {
    let c = locked_mem();
    let (e, text) = export(&c, "SELECT i FROM range(25) t(i) ORDER BY i", 10);
    assert_eq!(
        e,
        query::Exported {
            rows: 10,
            capped: true
        }
    );
    assert_eq!(text.lines().count(), 11);
    assert!(text.lines().last().unwrap() == "9");
    let (e, text) = export(&c, "SELECT i FROM range(10) t(i)", 10);
    assert_eq!(
        e,
        query::Exported {
            rows: 10,
            capped: false
        }
    );
    assert_eq!(text.lines().count(), 11);
    // More rows than sql_run's 10,000 limit, no LIMIT of its own.
    let (e, _) = export(&c, "SELECT i FROM range(25000) t(i)", query::EXPORT_CAP);
    assert_eq!(
        e,
        query::Exported {
            rows: 25_000,
            capped: false
        }
    );
    let (e, text) = export(&c, "SELECT i AS \"x\" FROM range(0) t(i)", 10);
    assert_eq!((e.rows, text.trim_start_matches('\u{feff}')), (0, "x\n"));
    // Refusals and errors write nothing.
    for bad in [
        "DELETE FROM findings",
        "SELECT nope FROM findings",
        "SELECT 1; SELECT 2",
    ] {
        let mut out = Vec::new();
        assert!(
            query::export_csv_on(&c, bad, &mut out, 10).is_err(),
            "{bad}"
        );
        assert!(out.is_empty(), "{bad}");
    }
    c.conn()
        .execute_batch("BEGIN TRANSACTION; ROLLBACK")
        .unwrap();
}

#[test]
fn query_icu_error_has_cast_hint() {
    let (_d, p) = case_file();
    let e = query::run(
        &p,
        "SELECT date_trunc('day', event_time) FROM ual_events",
        10,
    )
    .unwrap_err();
    let m = e.to_string();
    assert!(m.contains("CAST(event_time AS TIMESTAMP)"), "{m}");
    assert!(m.contains("\nhint: "), "{m}");
}

#[test]
fn query_timestamp_cast_works_without_icu() {
    let (_d, p) = case_file();
    let r = query::run(
        &p,
        "SELECT date_trunc('day', CAST(event_time AS TIMESTAMP)) d FROM ual_events",
        10,
    )
    .unwrap();
    assert_eq!(r.columns, ["d"]);
}

#[test]
fn query_keyword_alias_has_as_hint() {
    let (_d, p) = case_file();
    let e = query::run(&p, "SELECT 1 first", 10).unwrap_err();
    let m = e.to_string();
    assert!(m.contains("AS first"), "{m}");
    assert!(m.contains("\nhint: "), "{m}");
}
