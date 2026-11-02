//! `sparrow investigate` through the binary, over the shared events case (jdoe's events on 2026-09-01).

#[allow(dead_code)]
mod events_common;

use events_common::{build, json, run};

fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    (tmp, path)
}

#[test]
fn investigate_prints_sections() {
    let (_tmp, path) = setup();
    let r = run(&[
        "investigate",
        "--case",
        path.to_str().unwrap(),
        "--user",
        "jdoe@contoso.example",
        "--on",
        "2026-09-01",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    for heading in [
        "Sessions",
        "Mail to the account",
        "Mail sent",
        "Config changes",
        "Findings",
        "Next",
    ] {
        assert!(
            r.out.lines().any(|l| l.starts_with(heading)),
            "{heading}: {}",
            r.out
        );
    }
    assert!(r.out.contains(events_common::S1), "{}", r.out);
}

#[test]
fn investigate_json_has_next_steps() {
    let (_tmp, path) = setup();
    let p = path.to_str().unwrap();
    let v = json(&[
        "investigate",
        "--case",
        p,
        "--user",
        "jdoe@contoso.example",
        "--on",
        "2026-09-01",
        "--json",
    ]);
    assert_eq!(v["account"], "jdoe@contoso.example");
    let sessions = v["sessions"].as_array().unwrap();
    assert!(
        sessions.iter().any(|s| s["key"] == events_common::S1),
        "{v}"
    );
    let next = v["next"].as_array().unwrap();
    assert!(!next.is_empty());
    // Ready to run: `sparrow`, the arguments (quoted when they need it) and this case.
    assert!(
        next.iter().all(|n| {
            let c = n["command"].as_str().unwrap();
            c.starts_with("sparrow ")
                && (c.ends_with(&format!("--case {p}")) || c.ends_with(&format!("--case '{p}'")))
        }),
        "{v}"
    );
}

#[test]
fn on_with_pad_widens_the_day() {
    let (_tmp, path) = setup();
    let p = path.to_str().unwrap();
    let v = json(&[
        "investigate",
        "--case",
        p,
        "--user",
        "jdoe@contoso.example",
        "--on",
        "2026-09-01",
        "--pad",
        "12h",
        "--json",
    ]);
    assert_eq!(v["from"], "2026-08-31T12:00:00Z");
    assert_eq!(v["to"], "2026-09-02T12:00:00Z");
    let v = json(&[
        "investigate",
        "--case",
        p,
        "--user",
        "jdoe@contoso.example",
        "--from",
        "2026-09-01T10:00:00Z",
        "--to",
        "2026-09-01T10:06:00Z",
        "--json",
    ]);
    assert_eq!(v["sessions"].as_array().unwrap().len(), 1);
    // A window is required: --from/--to or --on.
    let r = run(&["investigate", "--case", p, "--user", "jdoe@contoso.example"]);
    assert_eq!(r.code, 1);
    let r = run(&[
        "investigate",
        "--case",
        p,
        "--user",
        "jdoe@contoso.example",
        "--on",
        "2026-09-01",
        "--pad",
        "1x",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("--pad"), "{}", r.err);
}

#[test]
fn an_empty_window_says_so() {
    let (_tmp, path) = setup();
    let r = run(&[
        "investigate",
        "--case",
        path.to_str().unwrap(),
        "--user",
        "jdoe@contoso.example",
        "--on",
        "2026-10-01",
    ]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.out.contains("no events of jdoe@contoso.example in"),
        "{}",
        r.out
    );
}
