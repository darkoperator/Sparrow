//! `sparrow access` through the binary: the per-account text, the CSV file and the Markdown summary, over the shared
//! events case with an accepted malicious IP flag (jdoe's 203.0.113.45).

mod events_common;

use events_common::{build, json, run};
use sparrow_core::Case;

fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = Case::create_or_open(&path).unwrap();
    case.conn()
        .execute_batch(
            "INSERT INTO value_flags (flag_id, kind, value, level, decided_by, decided_at, review_state) \
             VALUES ('vf1', 'ip', '203.0.113.45', 'malicious', 'analyst:carlos', TIMESTAMPTZ '2026-09-02 00:00:00+00', 'accepted')",
        )
        .unwrap();
    (tmp, path)
}

#[test]
fn access_prints_tiles_per_account() {
    let (_tmp, path) = setup();
    let r = run(&["access", "--case", path.to_str().unwrap()]);
    assert_eq!(r.code, 0, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(lines[0], "jdoe@contoso.example  tenant contoso");
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("  scope  ip 203.0.113.45  ")),
        "{}",
        r.out
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("  mail_read  0 direct  0 by time")),
        "{}",
        r.out
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("  other  2 direct  0 by time")),
        "{}",
        r.out
    );
    assert!(!r.out.contains("other@contoso.example"));
    let v = json(&["access", "--case", path.to_str().unwrap(), "--json"]);
    assert_eq!(v["accounts"][0]["account"], "jdoe@contoso.example");
    assert_eq!(v["accounts"][0]["tiles"].as_array().unwrap().len(), 7);
}

#[test]
fn access_csv_writes_the_file() {
    let (tmp, path) = setup();
    let out = tmp.path().join("access.csv");
    let r = run(&[
        "access",
        "--case",
        path.to_str().unwrap(),
        "--csv",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.starts_with("\u{feff}account,category,attribution,"));
    assert_eq!(text.lines().count(), 3, "{text}");
    assert!(r.out.contains("2 items"), "{}", r.out);
}

#[test]
fn access_markdown_prints_the_table() {
    let (_tmp, path) = setup();
    let r = run(&["access", "--case", path.to_str().unwrap(), "--markdown"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.starts_with("| Account | Emails read |"), "{}", r.out);
    assert!(r.out.contains("| jdoe@contoso.example |"));
}

#[test]
fn access_for_one_account() {
    let (_tmp, path) = setup();
    let v = json(&[
        "access",
        "--case",
        path.to_str().unwrap(),
        "--account",
        "OTHER@contoso.example",
        "--json",
    ]);
    assert_eq!(v["accounts"][0]["account"], "other@contoso.example");
    assert_eq!(v["accounts"][0]["items"].as_array().unwrap().len(), 0);
}

#[test]
fn access_csv_refuses_the_case_and_its_wal_and_keeps_the_case() {
    let (_tmp, path) = setup();
    let case = path.to_str().unwrap();
    let wal = format!("{case}.wal");
    let before = std::fs::metadata(&path).unwrap().len();
    for target in [case, wal.as_str()] {
        let r = run(&["access", "--case", case, "--csv", target]);
        assert_eq!(r.code, 5, "{target}: {}", r.err);
        assert!(r.err.contains("refusing to write"), "{}", r.err);
    }
    assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
    assert!(json(&["access", "--case", case, "--json"])["accounts"].is_array());
}

#[test]
fn access_json_conflicts_with_the_file_outputs() {
    let (tmp, path) = setup();
    let out = tmp.path().join("a.csv");
    let r = run(&[
        "access",
        "--case",
        path.to_str().unwrap(),
        "--json",
        "--csv",
        out.to_str().unwrap(),
    ]);
    assert_ne!(r.code, 0);
    assert!(!out.exists());
}

#[test]
fn access_csv_path_is_printed_terminal_safe() {
    let (tmp, path) = setup();
    let out = tmp.path().join("a\u{1b}[2Jb.csv");
    let r = run(&[
        "access",
        "--case",
        path.to_str().unwrap(),
        "--csv",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(!r.out.contains('\u{1b}'), "{:?}", r.out);
}
