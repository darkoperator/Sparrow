//! `sparrow coverage` through the binary on a small synthetic case (contoso.example): the exact text for one
//! account, the JSON shape, `--user` and that the command writes nothing.
//!
//! The case: tenant `t1`, one collection. carol has a finding first seen 2026-06-16 (window 2026-05-17..2026-07-31),
//! three UAL rows from a capped export (06-12 08:00, 06-12 09:00, 06-14 08:00), one interactive sign-in on 06-11 and
//! nothing else; bob's single UAL row on 07-31 makes 07-31 the tenant's last event.

use assert_cmd::Command;
use duckdb::params;
use serde_json::Value;
use sparrow_core::Case;

struct Run {
    code: i32,
    out: String,
    err: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn build(path: &std::path::Path) {
    let case = Case::create_or_open(path).unwrap();
    let c = case.conn();
    c.execute_batch(
        r##"INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('invictus', '/x/t1', 't', 't1');
         INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status, warnings)
             VALUES (1, 'cap.csv', 1, 'a', 'parsed', CAST('["row count equals known export cap 1000000 — results likely truncated"]' AS JSON)),
                    (1, 'ok.json', 1, 'b', 'parsed', NULL);
         INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, title,
                               actor_upn, first_seen, created_by, created_at, updated_at)
             VALUES ('f1', 'fp1', 't1', 'SPW-ID-004', 1, 'x', 'high', 't', 'carol@contoso.example',
                     CAST('2026-06-16 12:00:00+00' AS TIMESTAMPTZ), 'rule', now(), now());
         INSERT INTO account_rollup (tenant_key, upn, worst_severity, finding_count, by_severity, stages, rules,
                                     addresses, addresses_total, addresses_truncated, computed_run_id)
             VALUES ('t1', 'carol@contoso.example', 'high', 1, '{}', '[]', '[]', '[]', 0, false, 1);
         INSERT INTO signins (record_key, collection_id, event_time, event_type, user_upn)
             VALUES ('s1', 1, CAST('2026-06-11 09:00:00+00' AS TIMESTAMPTZ), 'interactive', 'carol@contoso.example');
         INSERT INTO record_sources VALUES ('signins', 's1', 2, 0, 1, 1, 0, 1, 'h');"##,
    )
    .unwrap();
    for (n, at, user, file) in [
        (1, "2026-06-12 08:00:00", "carol@contoso.example", 1),
        (2, "2026-06-12 09:00:00", "carol@contoso.example", 1),
        (3, "2026-06-14 08:00:00", "carol@contoso.example", 1),
        (4, "2026-07-31 08:00:00", "bob@contoso.example", 2),
    ] {
        let id = format!("00000000-0000-4000-8000-{n:012}");
        c.execute(
            "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision, \
                 organization_id, workload, operation, user_upn, audit_data, data_completeness, synthetic_id) \
             VALUES (CAST(? AS UUID), 1, CAST(? AS TIMESTAMPTZ), false, 'second', \
                 CAST('c9c9c9c9-0000-4000-8000-000000000001' AS UUID), 'Exchange', 'Send', ?, '{}', 'full', false)",
            params![id, format!("{at}+00"), user],
        )
        .unwrap();
        c.execute(
            "INSERT INTO record_sources VALUES ('ual_events', ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![id, file],
        )
        .unwrap();
    }
}

#[test]
fn coverage_through_the_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = path.to_str().unwrap();
    let rows_before = |sql: &str| -> i64 {
        let c = Case::open_read_only(&path).unwrap();
        c.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    };
    let audit_before = rows_before("SELECT count(*) FROM audit_trail");

    // ---- text, one account: the exact lines of the source block, then the requests ----
    let r = run(&["coverage", "--case", case]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        &lines[..8],
        [
            "carol@contoso.example  t1  window 2026-05-17..2026-07-31",
            "  ual  rows 3  2026-06-12..2026-06-14  2 days  SAMPLED",
            "  signins_interactive  rows 1  2026-06-11..2026-06-11  1 day",
            "  signins_noninteractive  absent",
            "  mail_items_accessed  absent",
            "  message_trace  absent",
            "  entra_audit  absent",
            "  mailbox_audit  absent",
        ],
        "{}",
        r.out
    );
    assert_eq!(
        lines[8],
        "  Request: ual  2026-05-17..2026-07-31  (before, sampled, after)"
    );
    assert_eq!(
        lines[9],
        "    console: Purview portal > Audit > Search: Users = carol@contoso.example, date range 2026-05-17 to 2026-07-31, Search, then Export (a per-user search stays under the 1,000,000-row cap)"
    );
    assert_eq!(lines[10], "    hawk: - (no matching command)");
    assert_eq!(
        lines[11],
        "    invictus: Get-UAL -UserIds carol@contoso.example -StartDate 2026-05-17 -EndDate 2026-08-01"
    );
    // One account, with a request per source that has a gap (seven sources, all with gaps), four lines each.
    assert_eq!(lines.len(), 8 + 7 * 4, "{}", r.out);

    // ---- JSON ----
    let r = run(&[
        "--json",
        "coverage",
        "--case",
        case,
        "--user",
        "CAROL@contoso.example",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["warnings"], serde_json::json!([]));
    let accounts = v["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    let a = &accounts[0];
    assert_eq!(a["upn"], "carol@contoso.example");
    assert_eq!(
        a["window"],
        serde_json::json!({"start": "2026-05-17", "end": "2026-07-31"})
    );
    let ual = &a["sources"][0];
    assert_eq!(ual["source"], "ual");
    assert_eq!(ual["rows"], 3);
    assert_eq!(ual["days"], 2);
    assert_eq!(ual["sampled"], true);
    assert_eq!(ual["first"], "2026-06-12T08:00:00.000000Z");
    assert_eq!(
        ual["gaps"],
        serde_json::json!([
            {"from": "2026-05-17", "to": "2026-06-11", "reason": "before"},
            {"from": "2026-06-12", "to": "2026-06-14", "reason": "sampled"},
            {"from": "2026-06-15", "to": "2026-07-31", "reason": "after"},
        ])
    );
    let req = &v["requests"][0];
    assert_eq!(req["source"], "ual");
    assert_eq!(req["hawk"], Value::Null);
    assert_eq!(
        req["reasons"],
        serde_json::json!(["before", "sampled", "after"])
    );

    // ---- --user for someone with no evidence; --tenant that does not exist ----
    let r = run(&[
        "coverage",
        "--case",
        case,
        "--user",
        "nobody@contoso.example",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.starts_with(
            "nobody@contoso.example  t1  window 2026-06-11..2026-07-31\n  ual  absent\n"
        ),
        "{}",
        r.out
    );
    let r = run(&[
        "coverage",
        "--case",
        case,
        "--tenant",
        "nope",
        "--user",
        "bob@contoso.example",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("no tenant"), "{}", r.err);

    // Read-only: the audit trail did not move.
    assert_eq!(
        rows_before("SELECT count(*) FROM audit_trail"),
        audit_before
    );
}

/// A case (and its temp dir) whose only evidence is a partial UAL manifest with one gap, tenant `t1`.
fn manifest_case() -> (tempfile::TempDir, std::path::PathBuf) {
    case_of(gap_manifest(), "case.duckdb")
}

/// A case `case_name` in a temp dir whose only evidence is `manifest` (in `CASE_OUTPUT/UALGraph`), tenant `t1`.
fn case_of(
    manifest: serde_json::Value,
    case_name: &str,
) -> (tempfile::TempDir, std::path::PathBuf) {
    use sparrow_core::ingest::parser::ParserRegistry;
    use sparrow_core::ingest::{IngestOptions, ingest_path};
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("CASE_OUTPUT");
    std::fs::create_dir_all(root.join("UALGraph")).unwrap();
    std::fs::write(
        root.join("LogFile.txt"),
        "2026-09-10 10:00:00: [INFO] Starting\n",
    )
    .unwrap();
    let run_id = manifest["run_id"].as_str().unwrap();
    std::fs::write(
        root.join("UALGraph")
            .join(format!("CollectionManifest-{run_id}.mesmanifest")),
        manifest.to_string(),
    )
    .unwrap();
    let path = tmp.path().join(case_name);
    {
        let mut case = Case::create_or_open(&path).unwrap();
        ingest_path(
            &mut case,
            tmp.path(),
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
        case.conn()
            .execute("UPDATE collections SET tenant_key = 't1'", [])
            .unwrap();
    }
    (tmp, path)
}

/// A partial UAL manifest with one search_timeout gap (and control characters in its texts).
fn gap_manifest() -> serde_json::Value {
    let run_id = "5b0f0c5e-0000-4000-8000-000000000001";
    serde_json::json!({
        "schema": "mes-collection-manifest/1", "run_id": run_id, "tool": "Microsoft-Extractor-Suite",
        "tool_version": "4.1.0.1", "fork": "f", "cmdlet": "Get-UALGraph",
        "parameters": {"UserIds": ["o'brien\u{1b}[31m@x.example"], "StartDate": "2026-08-01", "EndDate": "2026-09-11"},
        "started_utc": "2026-09-10T10:00:00Z", "finished_utc": "2026-09-10T11:00:00Z", "status": "partial",
        "throttle_waits": {"count": 0, "total_seconds": 0.0},
        "units": [{
            "unit_id": "u-0001", "sources": ["ual"],
            "scope": {"user_ids": null, "operations": null, "record_types": null, "ip_addresses": null,
                      "session_ids": null, "event_type": null, "direction": null, "other_filters": null},
            "start_utc": "2026-08-01T00:00:00Z", "end_utc": "2026-09-11T00:00:00Z", "state": "partial",
            "records_written": 0, "output_written": true, "files": [],
            "gaps": [{"start_utc": "2026-09-04T00:00:00Z", "end_utc": "2026-09-06T00:00:00Z",
                      "reason": "search_timeout", "detail": "slow\u{1b}[2J", "attempts": null,
                      "records_in_window": null, "search_id": "sid-1"}]
        }]
    })
}

#[test]
fn coverage_prints_manifest_gaps_first() {
    let (_tmp, path) = manifest_case();
    let r = run(&["coverage", "--case", path.to_str().unwrap()]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        lines[0], "Collector gaps (re-run these first):",
        "{}",
        r.out
    );
    assert_eq!(
        lines[1],
        "  ual  2026-09-04T00:00:00Z..2026-09-06T00:00:00Z  search_timeout  run 5b0f0c5e-0000-4000-8000-000000000001 unit u-0001"
    );
    assert!(lines[2].starts_with("    detail: slow"), "{}", r.out);
    assert!(!r.out.contains('\u{1b}'), "{:?}", r.out);
    assert!(
        lines[3].starts_with("    rerun: Get-UALGraph -UserIds 'o''brien"),
        "{}",
        r.out
    );
    assert!(
        lines[3].ends_with("-StartDate '2026-09-04T00:00:00Z' -EndDate '2026-09-06T00:00:00Z'"),
        "{}",
        r.out
    );
    assert_eq!(lines[4], "    resume: Get-UALGraph -SearchId 'sid-1'");
    let j = run(&["--json", "coverage", "--case", path.to_str().unwrap()]);
    let v: Value = serde_json::from_str(&j.out).unwrap();
    assert_eq!(v["collector_requests"].as_array().unwrap().len(), 1);
}

#[test]
fn coverage_warns_on_stderr_about_an_incomplete_collection() {
    let (_tmp, path) = manifest_case();
    let r = run(&["coverage", "--case", path.to_str().unwrap()]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.err.contains("warning: Collection incomplete: 1 gap in Unified audit log (2 days). Re-collect before relying on absence of activity."),
        "{}",
        r.err
    );
    assert!(!r.out.contains("Collection incomplete"), "{}", r.out);
}

#[test]
fn summary_prints_the_banner() {
    let (_tmp, path) = manifest_case();
    {
        let case = Case::create_or_open(&path).unwrap();
        case.conn()
            .execute(
                "INSERT INTO tenant (tenant_key, collections) VALUES ('t1', 1)",
                [],
            )
            .unwrap();
    }
    let p = path.to_str().unwrap();
    let r = run(&["summary", "--case", p]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        lines[0],
        "Collection incomplete: 1 gap in Unified audit log (2 days). Re-collect before relying on absence of activity."
    );
    assert_eq!(
        lines[1],
        format!("  pull list: sparrow coverage --case {p}")
    );
    let j = run(&["--json", "summary", "--case", p]);
    let v: Value = serde_json::from_str(&j.out).unwrap();
    assert_eq!(v["incomplete_collection"]["gaps"], 1);
    assert_eq!(v["incomplete_collection"]["sources"][0], "ual");
}

#[test]
fn ingest_prints_the_banner_after_the_profile_summary() {
    let (tmp, _) = manifest_case();
    let case = tmp.path().join("again.duckdb");
    let r = run(&[
        "ingest",
        tmp.path().join("CASE_OUTPUT").to_str().unwrap(),
        "--case",
        case.to_str().unwrap(),
    ]);
    assert!(matches!(r.code, 0 | 6), "{} {}", r.code, r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with("Collection incomplete: 1 gap"))
        .unwrap_or_else(|| panic!("{}", r.out));
    assert!(lines[..at].iter().any(|l| l.starts_with("profile:")));
    assert_eq!(
        lines[at + 1],
        format!("  pull list: sparrow coverage --case {}", case.display())
    );
}

// ---- final fix wave ----

/// A `Get-UALGraph -SearchId` run that failed before it created its unit.
fn unitless_failed_manifest() -> serde_json::Value {
    serde_json::json!({
        "schema": "mes-collection-manifest/1", "run_id": "5b0f0c5e-0000-4000-8000-000000000002",
        "tool": "Microsoft-Extractor-Suite", "tool_version": "4.1.0.1", "fork": "f", "cmdlet": "Get-UALGraph",
        "parameters": {"SearchId": "sid-2"},
        "started_utc": "2026-09-10T10:00:00Z", "finished_utc": "2026-09-10T11:00:00Z", "status": "failed",
        "throttle_waits": {"count": 0, "total_seconds": 0.0}, "units": []
    })
}

fn add_tenant(path: &std::path::Path) {
    let case = Case::create_or_open(path).unwrap();
    case.conn()
        .execute(
            "INSERT INTO tenant (tenant_key, collections) VALUES ('t1', 1)",
            [],
        )
        .unwrap();
}

#[test]
fn a_run_that_failed_before_its_unit_is_pulled_with_unknown_sources() {
    let (_tmp, path) = case_of(unitless_failed_manifest(), "case.duckdb");
    let p = path.to_str().unwrap();
    let r = run(&["coverage", "--case", p]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        lines[0], "Collector gaps (re-run these first):",
        "{}",
        r.out
    );
    assert_eq!(
        lines[1],
        "  unknown sources  undated  run_failed  run 5b0f0c5e-0000-4000-8000-000000000002"
    );
    assert_eq!(lines[2], "    rerun: Get-UALGraph -SearchId 'sid-2'");
    assert_eq!(lines[3], "    resume: Get-UALGraph -SearchId 'sid-2'");
    assert!(
        r.err
            .contains("warning: Collection incomplete: 1 gap in unknown sources (unknown span)."),
        "{}",
        r.err
    );
    add_tenant(&path);
    let s = run(&["summary", "--case", p]);
    assert!(
        s.out
            .starts_with("Collection incomplete: 1 gap in unknown sources (unknown span)."),
        "{}",
        s.out
    );
}

/// `'`-quoted for a POSIX shell, as the app quotes it.
fn quoted(p: &std::path::Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

#[test]
fn the_pull_list_line_quotes_a_case_path_with_spaces() {
    let (_tmp, path) = case_of(gap_manifest(), "my case's.duckdb");
    add_tenant(&path);
    let r = run(&["summary", "--case", path.to_str().unwrap()]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(
        lines[1],
        format!("  pull list: sparrow coverage --case {}", quoted(&path))
    );
    assert!(lines[1].ends_with(r"/my case'\''s.duckdb'"), "{}", lines[1]);
}

#[test]
fn ingest_quotes_the_pull_list_path_and_escapes_file_names_and_warnings() {
    let (tmp, _) = manifest_case();
    // A message trace export whose name holds a format character (RTL override) and whose header holds ESC: the
    // file is not supported and its warning names the header.
    let dir = tmp.path().join("CASE_OUTPUT/MessageTrace/20260910-100000");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("x\u{202e}y-MessageTrace.csv"),
        "Bad\u{1b}[31mCol,Other\n1,2\n",
    )
    .unwrap();
    let case = tmp.path().join("again case.duckdb");
    let r = run(&[
        "ingest",
        tmp.path().join("CASE_OUTPUT").to_str().unwrap(),
        "--case",
        case.to_str().unwrap(),
    ]);
    assert!(matches!(r.code, 0 | 2 | 6), "{} {}", r.code, r.err);
    assert!(!r.out.contains('\u{1b}'), "{:?}", r.out);
    assert!(!r.out.contains('\u{202e}'), "{:?}", r.out);
    let file = r
        .out
        .lines()
        .find(|l| l.contains("-MessageTrace.csv"))
        .unwrap_or_else(|| panic!("{}", r.out));
    assert!(file.contains(r"x\u{202E}y-MessageTrace.csv"), "{file}");
    assert!(file.contains(r"Bad\u{001B}[31mCol"), "{file}");
    let lines: Vec<&str> = r.out.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with("Collection incomplete: 1 gap"))
        .unwrap_or_else(|| panic!("{}", r.out));
    assert_eq!(
        lines[at + 1],
        format!("  pull list: sparrow coverage --case {}", quoted(&case))
    );
    // JSON keeps the raw text.
    let case2 = tmp.path().join("json.duckdb");
    let j = run(&[
        "--json",
        "ingest",
        tmp.path().join("CASE_OUTPUT").to_str().unwrap(),
        "--case",
        case2.to_str().unwrap(),
    ]);
    let v: Value = serde_json::from_str(&j.out).unwrap_or_else(|e| panic!("{e}: {}", j.out));
    let raw = v.to_string();
    assert!(raw.contains("x\u{202e}y-MessageTrace.csv"), "{raw:?}");
}
