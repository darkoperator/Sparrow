//! `--snapshot`: a read-only command on a case another process holds reads a private copy, deleted afterwards; the
//! lock error names the option; writes never snapshot.

#[allow(dead_code)]
mod events_common;

use assert_cmd::Command;
use events_common::build;
use sparrow_core::Case;
use std::path::Path;

fn sparrow(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut c = Command::cargo_bin("sparrow").unwrap();
    c.env("SPARROW_BRIDGE", "off")
        .env_remove("SPARROW_SNAPSHOT");
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.current_dir(dir).args(args).output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Leftover snapshot directories beside the case.
fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".sparrow-snapshot-"))
        .collect()
}

/// A case held open for writing by this process (as the app holds it), and its directory.
fn held() -> (tempfile::TempDir, std::path::PathBuf, Case) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let case = Case::create_or_open(&path).unwrap();
    (tmp, path, case)
}

#[test]
fn snapshot_reads_a_case_held_by_a_writer() {
    let (tmp, path, _held) = held();
    let p = path.to_str().unwrap();
    let (code, out, err) = sparrow(
        tmp.path(),
        &["events", "--case", p, "--snapshot", "--json"],
        &[],
    );
    assert_eq!(code, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v["snapshot"]["taken_at"].is_string(), "{v}");
    assert!(
        v["rows"].as_array().is_some_and(|r| !r.is_empty()),
        "the copy has the case's events: {v}"
    );
    assert!(err.contains("note: read a snapshot of"), "{err}");
    assert!(leftovers(tmp.path()).is_empty(), "the copy is gone");
    // The environment variable does the same.
    let (code, _, err) = sparrow(
        tmp.path(),
        &["events", "--case", p],
        &[("SPARROW_SNAPSHOT", "1")],
    );
    assert_eq!(code, 0, "{err}");
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn without_snapshot_the_lock_error_names_the_option() {
    let (tmp, path, _held) = held();
    let (code, out, err) = sparrow(
        tmp.path(),
        &["events", "--case", path.to_str().unwrap()],
        &[],
    );
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("--snapshot"), "{err}");
    assert_eq!(out, "");
}

#[test]
fn write_commands_never_snapshot() {
    let (tmp, path, _held) = held();
    let (code, _, err) = sparrow(
        tmp.path(),
        &[
            "mark",
            "flag",
            "--case",
            path.to_str().unwrap(),
            "--row",
            "ual_events:u1",
            "--level",
            "malicious",
            "--snapshot",
        ],
        &[],
    );
    assert_eq!(code, 4, "{err}");
    assert!(!err.contains("snapshot of"), "{err}");
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn a_free_case_is_read_directly() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let (code, out, err) = sparrow(
        tmp.path(),
        &[
            "events",
            "--case",
            path.to_str().unwrap(),
            "--snapshot",
            "--json",
        ],
        &[],
    );
    assert_eq!(code, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(
        v.get("snapshot").is_none(),
        "no copy when the file is free: {v}"
    );
}
