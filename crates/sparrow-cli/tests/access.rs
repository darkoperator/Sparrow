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

#[test]
fn access_preview_prints_the_banner_and_chips() {
    let (_tmp, path) = setup();
    let p = path.to_str().unwrap();
    // The accepted flag alone: no banner.
    let r = run(&["access", "--case", p, "--include-pending"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(!r.out.starts_with("PREVIEW"), "{}", r.out);
    // An ad-hoc address of the other account's events: a preview, its chip says so.
    let r = run(&["access", "--case", p, "--ip", "192.0.2.9"]);
    assert_eq!(r.code, 0, "{}", r.err);
    let first = r.out.lines().next().unwrap();
    assert_eq!(
        first,
        "PREVIEW: includes pending or ad-hoc scope; not the reviewed report"
    );
    assert!(
        r.out
            .lines()
            .any(|l| l.starts_with("  scope  AD-HOC ip 192.0.2.9  ")),
        "{}",
        r.out
    );
    assert!(
        r.out
            .lines()
            .any(|l| l.starts_with("  scope  ip 203.0.113.45  ")),
        "{}",
        r.out
    );
    // The other account's tile counts are ad-hoc: its line says so.
    assert!(
        r.out
            .lines()
            .any(|l| l.starts_with("  other  1 direct  0 by time  AD-HOC 1")),
        "{}",
        r.out
    );
    let v = json(&["access", "--case", p, "--ip", "192.0.2.9", "--json"]);
    assert_eq!(v["preview"], true);
    let other = v["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["account"] == "other@contoso.example")
        .unwrap();
    assert_eq!(other["scope"][0]["basis"], "adhoc");
    assert!(
        other["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["basis"] == "adhoc")
    );
    // A bad address is refused, not silently empty.
    let r = run(&["access", "--case", p, "--ip", "1.2.3.4' OR 1=1 --"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("not an IP"), "{}", r.err);
}

#[test]
fn access_brief_has_no_items() {
    let (_tmp, path) = setup();
    let v = json(&[
        "access",
        "--case",
        path.to_str().unwrap(),
        "--brief",
        "--json",
    ]);
    let a = &v["accounts"][0];
    assert_eq!(a["account"], "jdoe@contoso.example");
    assert!(a.get("items").is_none(), "{a}");
    assert_eq!(a["tiles"].as_array().unwrap().len(), 7);
    let w = &a["scope"][0]["windows"];
    assert_eq!(w["count"], 1);
    assert!(w["first"].is_string() && w["last"].is_string(), "{w}");
    assert_eq!(v["never_logged"].as_array().unwrap().len(), 4);
    // The text says the same, one line per scope value.
    let r = run(&["access", "--case", path.to_str().unwrap(), "--brief"]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out
            .lines()
            .any(|l| l.starts_with("  scope  ip 203.0.113.45  1 window  ")),
        "{}",
        r.out
    );
}

#[test]
fn access_category_pages() {
    let (_tmp, path) = setup();
    let p = path.to_str().unwrap();
    let all = json(&["access", "--case", p, "--category", "other", "--json"]);
    let a = &all["accounts"][0];
    assert_eq!(a["category"], "other");
    assert_eq!(a["total"], 2);
    let items = a["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(
        items
            .iter()
            .all(|i| i["category"] == "other" && i["row"].as_str().unwrap().contains(':'))
    );
    let page = json(&[
        "access",
        "--case",
        p,
        "--category",
        "other",
        "--limit",
        "1",
        "--offset",
        "1",
        "--json",
    ]);
    let a = &page["accounts"][0];
    assert_eq!(a["total"], 2);
    assert_eq!(a["items"].as_array().unwrap().len(), 1);
    assert_eq!(a["items"][0]["row"], items[1]["row"]);
    let r = run(&["access", "--case", p, "--category", "nope"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("mail_read"), "{}", r.err);
}

#[test]
fn paging_past_the_end() {
    let (_tmp, path) = setup();
    let v = json(&[
        "access",
        "--case",
        path.to_str().unwrap(),
        "--category",
        "other",
        "--offset",
        "50",
        "--json",
    ]);
    let a = &v["accounts"][0];
    assert_eq!(a["total"], 2);
    assert_eq!(a["items"].as_array().unwrap().len(), 0);
}

#[test]
fn compact_text_keeps_the_preview_marks_and_the_context() {
    let (_tmp, path) = setup();
    let p = path.to_str().unwrap();
    let r = run(&[
        "access",
        "--case",
        p,
        "--category",
        "other",
        "--ip",
        "192.0.2.9",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    let head = r
        .out
        .lines()
        .find(|l| l.starts_with("other@contoso.example  other"))
        .unwrap_or_else(|| panic!("{}", r.out));
    assert!(head.contains("AD-HOC 1"), "{head}");
    assert!(
        r.out.lines().any(|l| l.starts_with("never logged  ")),
        "{}",
        r.out
    );
    // An empty report still says what Microsoft never logs.
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("empty.duckdb");
    events_common::build(&empty);
    let r = run(&["access", "--case", empty.to_str().unwrap()]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.lines().any(|l| l.starts_with("never logged  ")),
        "{}",
        r.out
    );
}
