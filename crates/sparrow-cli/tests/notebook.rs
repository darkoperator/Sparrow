//! `sparrow notebook`: the built-in and case notebooks from the CLI, as an agent uses them.

mod events_common;

use events_common::{build, json, run};
use sparrow_core::Case;
use std::ffi::OsString;
use std::path::Path;

fn setup() -> (tempfile::TempDir, String) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let p = path.to_str().unwrap().to_string();
    (tmp, p)
}

fn agent() -> [&'static str; 4] {
    ["--agent", "claude", "--analyst", "carlos"]
}

#[test]
fn list_shows_the_builtin_on_a_new_case() {
    let (_t, case) = setup();
    let v = json(&["--json", "notebook", "list", "--case", &case]);
    let nbs = v["notebooks"].as_array().unwrap();
    assert_eq!(nbs.len(), 1);
    assert_eq!(nbs[0]["builtin"], true);
    assert_eq!(nbs[0]["queries"].as_array().unwrap().len(), 12);
    let plain = run(&["notebook", "list", "--case", &case]);
    assert_eq!(plain.code, 0, "{}", plain.err);
    assert!(plain.out.contains("Built-in"), "{}", plain.out);
    assert!(plain.out.contains("[ip]"), "{}", plain.out);
}

#[test]
fn an_agent_adds_and_runs_a_query() {
    let (_t, case) = setup();
    let mut args = vec![
        "notebook",
        "add",
        "--case",
        &case,
        "--notebook",
        "Triage",
        "--create",
        "--sql",
        "-- T\nSELECT 42 AS n",
    ];
    args.extend(agent());
    let r = run(&args);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("added to Triage"), "{}", r.out);
    let v = json(&["--json", "notebook", "run", "Triage", "1", "--case", &case]);
    assert_eq!(v["rows"], serde_json::json!([[42]]));
    let v = json(&["--json", "notebook", "show", "triage", "1", "--case", &case]);
    assert_eq!(v["sql"], "-- T\nSELECT 42 AS n");
    assert_eq!(v["decided_by"], "agent:claude");
    // Without --create an unknown notebook is refused.
    let mut args = vec![
        "notebook",
        "add",
        "--case",
        &case,
        "--notebook",
        "Nope",
        "--sql",
        "SELECT 1",
    ];
    args.extend(agent());
    assert_eq!(run(&args).code, 5);
}

#[test]
fn an_agent_cannot_add_to_the_builtin() {
    let (_t, case) = setup();
    let mut args = vec![
        "notebook",
        "add",
        "--case",
        &case,
        "--notebook",
        "Built-in",
        "--sql",
        "SELECT 1",
    ];
    args.extend(agent());
    let r = run(&args);
    assert_eq!(r.code, 5);
    assert!(
        r.err.contains("the built-in notebook cannot be changed"),
        "{}",
        r.err
    );
}

#[test]
fn run_refuses_unfilled_placeholders() {
    let (_t, case) = setup();
    let r = run(&["notebook", "run", "builtin", "12", "--case", &case]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("Fill in [ip] first"), "{}", r.err);
}

#[test]
fn export_refuses_case_values_without_force() {
    let (t, case) = setup();
    let ip: String = Case::open_read_only(Path::new(&case))
        .unwrap()
        .conn()
        .query_row(
            "SELECT ip FROM events WHERE ip IS NOT NULL LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let sql = format!("-- Mine\nSELECT 1 WHERE '{ip}' <> ''");
    let mut args = vec![
        "notebook",
        "add",
        "--case",
        &case,
        "--notebook",
        "Mine",
        "--create",
        "--sql",
        &sql,
    ];
    args.extend(agent());
    assert_eq!(run(&args).code, 0);
    let out = t.path().join("mine.sql");
    let o = out.to_str().unwrap();
    let r = run(&["notebook", "export", "Mine", "--out", o, "--case", &case]);
    assert_eq!(r.code, 5, "{}", r.err);
    assert!(r.err.contains(&ip), "{}", r.err);
    assert!(!out.exists());
    let v = json(&[
        "--json", "notebook", "export", "Mine", "--out", o, "--force", "--case", &case,
    ]);
    assert_eq!(v["case_values"][0]["values"][0], ip.as_str());
    assert!(
        std::fs::read_to_string(&out)
            .unwrap()
            .starts_with("-- sparrow notebook: Mine\n")
    );
}

#[test]
fn import_round_trips() {
    let (t, case) = setup();
    let out = t.path().join("b.sql");
    let o = out.to_str().unwrap();
    let r = run(&["notebook", "export", "builtin", "--out", o, "--case", &case]);
    assert_eq!(r.code, 0, "{}", r.err);
    let mut args = vec!["notebook", "import", "--file", o, "--case", &case];
    args.extend(agent());
    let r = run(&args);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out
            .contains("imported 12 queries as notebook Built-in (copy)"),
        "{}",
        r.out
    );
    let v = json(&["--json", "notebook", "list", "--case", &case]);
    assert_eq!(v["notebooks"][1]["name"], "Built-in (copy)");
}

#[test]
fn notebook_writes_are_bridge_writes() {
    use sparrow_cli::{Kind, inspect};
    let k = |args: &[&str]| {
        let v: Vec<OsString> = std::iter::once("sparrow")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect();
        inspect(&v).kind
    };
    assert_eq!(
        k(&[
            "notebook",
            "add",
            "--case",
            "c",
            "--notebook",
            "n",
            "--sql",
            "x"
        ]),
        Kind::Write("notebooks")
    );
    assert_eq!(
        k(&["notebook", "import", "--file", "f", "--case", "c"]),
        Kind::Write("notebooks")
    );
    assert_eq!(k(&["notebook", "list", "--case", "c"]), Kind::Read);
    assert_eq!(
        k(&["notebook", "show", "a", "1", "--case", "c"]),
        Kind::Read
    );
    assert_eq!(k(&["notebook", "run", "a", "1", "--case", "c"]), Kind::Read);
    assert_eq!(
        k(&["notebook", "export", "a", "--out", "f", "--case", "c"]),
        Kind::Read
    );
}

#[test]
fn a_refused_add_with_create_leaves_no_notebook() {
    let (_t, case) = setup();
    let audit = |c: &str| -> i64 {
        Case::open_read_only(Path::new(c))
            .unwrap()
            .conn()
            .query_row("SELECT count(*) FROM audit_trail", [], |r| r.get(0))
            .unwrap()
    };
    let before = audit(&case);
    let mut args = vec![
        "notebook",
        "add",
        "--case",
        &case,
        "--notebook",
        "New",
        "--create",
        "--sql",
        " ",
    ];
    args.extend(agent());
    let r = run(&args);
    assert_eq!(r.code, 5, "{}", r.err);
    let v = json(&["--json", "notebook", "list", "--case", &case]);
    assert_eq!(v["notebooks"].as_array().unwrap().len(), 1);
    assert_eq!(audit(&case), before);
}

#[test]
fn show_escapes_terminal_controls() {
    let (_t, case) = setup();
    let mut args = vec![
        "notebook",
        "add",
        "--case",
        &case,
        "--notebook",
        "T",
        "--create",
        "--sql",
        "-- x\u{1b}[2J\nSELECT 1",
    ];
    args.extend(agent());
    assert_eq!(run(&args).code, 0);
    let r = run(&["notebook", "show", "T", "1", "--case", &case]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(!r.out.contains('\u{1b}'), "{:?}", r.out);
    assert!(r.out.contains("\\u{001B}"), "{:?}", r.out);
    assert!(r.out.contains("\nSELECT 1"), "{:?}", r.out);
}

#[test]
fn a_shown_query_runs_with_sparrow_query_after_filling_in() {
    let (_t, case) = setup();
    let v = json(&["--json", "notebook", "show", "builtin", "12", "--case", &case]);
    let sql = v["sql"].as_str().unwrap().replace("[ip]", "203.0.113.7");
    assert!(sql.starts_with("--"));
    let r = run(&["query", &sql, "--case", &case]);
    assert_eq!(r.code, 0, "{}", r.err);
}
