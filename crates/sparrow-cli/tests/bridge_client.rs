//! The CLI's side of the agent bridge, through the binary: when it forwards a command to the app, and when it runs
//! it here. A fake app (a loopback listener) stands in for the real one.
//!
//! Unix only: the fake app is found through `SPARROW_BRIDGE_DIR`, which Windows deliberately ignores (only the profile's
//! own directory is trusted to keep the token private).
#![cfg(unix)]

#[allow(dead_code)]
mod events_common;

use assert_cmd::Command;
use events_common::build;
use sparrow_cli::bridge::{Discovery, EXIT, OUT, VERSION, write_discovery, write_frame};
use std::io::BufRead;
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc;

/// A fake app answering one request with `from-bridge` and exit 0; the receiver gets the request line it read.
fn fake_app() -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        let mut r = std::io::BufReader::new(s.try_clone().unwrap());
        let (mut token, mut req) = (String::new(), String::new());
        r.read_line(&mut token).unwrap();
        r.read_line(&mut req).unwrap();
        write_frame(&mut s, OUT, b"from-bridge\n").unwrap();
        write_frame(&mut s, EXIT, &[0]).unwrap();
        let _ = tx.send(req);
    });
    (port, rx)
}

fn discovery(case: &Path, port: u16, pid: u32, version: &str) -> Discovery {
    Discovery {
        port,
        token: "ab".repeat(32),
        case: std::fs::canonicalize(case).unwrap(),
        pid,
        version: version.to_string(),
        started: chrono::Utc::now(),
    }
}

fn sparrow(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .env("SPARROW_BRIDGE_DIR", dir)
        .env_remove("SPARROW_BRIDGE")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case.duckdb");
    build(&case);
    let dir = tmp.path().join("bridge");
    (tmp, case, dir)
}

#[test]
fn the_app_answers_for_the_case_it_holds() {
    let (_tmp, case, dir) = setup();
    let (port, got) = fake_app();
    write_discovery(&dir, &discovery(&case, port, std::process::id(), VERSION)).unwrap();
    let (code, out, err) = sparrow(&dir, &["events", "--case", case.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "from-bridge\n");
    let req: serde_json::Value = serde_json::from_str(
        &got.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the app was asked"),
    )
    .unwrap();
    assert_eq!(req["args"][0], "events");
    assert_eq!(req["version"], VERSION);
}

#[test]
fn relative_paths_reach_the_app_absolute() {
    let (tmp, case, dir) = setup();
    let (port, got) = fake_app();
    write_discovery(&dir, &discovery(&case, port, std::process::id(), VERSION)).unwrap();
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .current_dir(tmp.path())
        .env("SPARROW_BRIDGE_DIR", &dir)
        .args(["access", "--case", "case.duckdb", "--csv", "out.csv"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let req: serde_json::Value = serde_json::from_str(
        &got.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the app was asked"),
    )
    .unwrap();
    let args: Vec<&str> = req["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    let cwd = std::fs::canonicalize(tmp.path()).unwrap();
    let abs = |p: &str| {
        let a = Path::new(args[args.iter().position(|x| *x == p).unwrap() + 1]);
        assert!(a.is_absolute(), "{p} {a:?}");
        std::fs::canonicalize(a.parent().unwrap()).unwrap()
    };
    assert_eq!(abs("--case"), cwd);
    assert_eq!(abs("--csv"), cwd);
}

#[test]
fn a_stale_discovery_file_is_ignored() {
    let (_tmp, case, dir) = setup();
    // A process that has exited: its pid is free.
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let dead = child.id();
    child.wait().unwrap();
    let (port, _got) = fake_app();
    write_discovery(&dir, &discovery(&case, port, dead, VERSION)).unwrap();
    let (code, out, err) = sparrow(
        &dir,
        &["events", "--case", case.to_str().unwrap(), "--json"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("\"rows\"") && !out.contains("from-bridge"),
        "ran here: {out}"
    );
}

#[test]
fn no_bridge_flag_runs_locally() {
    let (_tmp, case, dir) = setup();
    let (port, got) = fake_app();
    write_discovery(&dir, &discovery(&case, port, std::process::id(), VERSION)).unwrap();
    let (code, out, err) = sparrow(
        &dir,
        &[
            "events",
            "--case",
            case.to_str().unwrap(),
            "--json",
            "--no-bridge",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("from-bridge"));
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .env("SPARROW_BRIDGE_DIR", &dir)
        .env("SPARROW_BRIDGE", "off")
        .args(["events", "--case", case.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("from-bridge"));
    assert!(got.try_recv().is_err(), "the fake app was never asked");
}

#[test]
fn another_case_runs_locally() {
    let (tmp, case, dir) = setup();
    let other = tmp.path().join("other.duckdb");
    build(&other);
    let (port, got) = fake_app();
    write_discovery(&dir, &discovery(&other, port, std::process::id(), VERSION)).unwrap();
    let (code, out, err) = sparrow(&dir, &["events", "--case", case.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("from-bridge"));
    assert!(got.try_recv().is_err());
}

#[test]
fn a_version_mismatch_refuses() {
    let (_tmp, case, dir) = setup();
    let (port, _got) = fake_app();
    write_discovery(&dir, &discovery(&case, port, std::process::id(), "0.0.1")).unwrap();
    let (code, _, err) = sparrow(&dir, &["events", "--case", case.to_str().unwrap()]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("update the CLI or the app"), "{err}");
}

/// A listener that accepts each connection and closes it without answering (an app whose bridge is wedged).
fn mute_app() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            drop(s);
        }
    });
    port
}

#[test]
fn a_refused_connection_runs_here() {
    let (_tmp, case, dir) = setup();
    // A live pid (a reused one, or an app whose bridge is gone) but nothing listening: no bridge, so the file decides.
    let port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    write_discovery(&dir, &discovery(&case, port, std::process::id(), VERSION)).unwrap();
    let (code, out, err) = sparrow(
        &dir,
        &["events", "--case", case.to_str().unwrap(), "--json"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("\"rows\""), "ran here: {out}");
    // A sandbox that blocks localhost also refuses: the note keeps that hint.
    assert!(
        err.contains("refused") && err.contains("localhost"),
        "{err}"
    );
}

#[test]
fn an_app_that_does_not_answer_is_explained() {
    let (_tmp, case, dir) = setup();
    write_discovery(
        &dir,
        &discovery(&case, mute_app(), std::process::id(), VERSION),
    )
    .unwrap();
    let (code, _, err) = sparrow(&dir, &["events", "--case", case.to_str().unwrap()]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("--snapshot"), "{err}");
    assert!(err.contains("gave no answer"), "{err}");
}

#[test]
fn an_unreachable_app_falls_back_to_the_snapshot_when_asked() {
    let (_tmp, case, dir) = setup();
    write_discovery(
        &dir,
        &discovery(&case, mute_app(), std::process::id(), VERSION),
    )
    .unwrap();
    let (code, out, err) = sparrow(
        &dir,
        &[
            "events",
            "--case",
            case.to_str().unwrap(),
            "--snapshot",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("did not answer"), "{err}");
    assert!(out.contains("\"rows\""), "{out}");
}
