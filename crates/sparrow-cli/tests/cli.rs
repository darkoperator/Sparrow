use assert_cmd::Command;
use predicates::str::contains;
use serde_json::Value;
use sparrow_core::fixtures;

fn sparrow() -> Command {
    Command::cargo_bin("sparrow").unwrap()
}

fn json_out(cmd: &mut Command, expected_code: i32) -> Value {
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(expected_code),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn prints_version() {
    sparrow()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains("sparrow 0.1.0"));
}

#[test]
fn discover_lists_collections_and_classifications() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    fixtures::invictus_tree(dir.path());
    let v = json_out(sparrow().args(["--json", "discover"]).arg(dir.path()), 0);
    let cols = v["collections"].as_array().unwrap();
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0]["tool"], "hawk");
    let files = cols[0]["files"].as_array().unwrap();
    let log = files.iter().find(|f| f["rel_path"] == "Hawk.log").unwrap();
    assert_eq!(log["artifact_id"], "hawk.log");
    let unknown = files
        .iter()
        .find(|f| f["rel_path"] == "notes/random.bin")
        .unwrap();
    assert!(unknown["artifact_id"].is_null());
}

#[test]
fn ingest_then_reingest_then_verify_then_schema() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");

    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case)
            .args(["--culture", "en-US"]),
        0,
    );
    let files = v["collections"][0]["files"].as_array().unwrap();
    assert_eq!(
        files.iter().find(|f| f["rel_path"] == "Hawk.log").unwrap()["status"],
        "parsed"
    );

    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case),
        0,
    );
    let files = v["collections"][0]["files"].as_array().unwrap();
    // Task 10 controller ruling: on re-ingest, previously `parsed` files report
    // `duplicate_file`; files that were `not_supported` / `unrecognized` are retried
    // and report that status again, not `duplicate_file`.
    assert_eq!(
        files.iter().find(|f| f["rel_path"] == "Hawk.log").unwrap()["status"],
        "duplicate_file",
        "{files:?}"
    );
    assert!(
        files
            .iter()
            .all(|f| f["status"] != "parsed" && f["status"] != "error"),
        "{files:?}"
    );

    let file_id = v["collections"][0]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rel_path"] == "Hawk.log")
        .unwrap()["file_id"]
        .as_i64()
        .unwrap();
    let key = format!("{file_id}:8");
    let v = json_out(
        sparrow()
            .args(["--json", "verify", "collection_log", &key, "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(v["ok"], true);
    assert!(
        v["sightings"][0]["source_ref"]
            .as_str()
            .unwrap()
            .ends_with("Hawk.log:9-10")
    );

    let v = json_out(
        sparrow()
            .args(["--json", "schema", "source_files", "--case"])
            .arg(&case),
        0,
    );
    let t = &v["tables"][0];
    assert_eq!(t["table"], "source_files");
    assert!(t["comment"].as_str().unwrap().contains("SHA-256"));
    assert!(
        t["columns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "sha256")
    );
}

#[test]
fn ingest_with_file_errors_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case)
            .args(["--max-file-size", "10"]),
        2,
    );
    assert!(
        v["collections"][0]["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["status"] == "error")
    );
}

#[test]
fn bad_culture_and_missing_path_exit_1_with_message() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    sparrow()
        .arg("ingest")
        .arg(dir.path())
        .arg("--case")
        .arg(&case)
        .args(["--culture", "xx-YY"])
        .assert()
        .code(1)
        .stderr(contains("error:"))
        .stderr(contains("unsupported culture"));
    sparrow()
        .arg("ingest")
        .arg(dir.path().join("does-not-exist"))
        .arg("--case")
        .arg(&case)
        .assert()
        .code(1)
        .stderr(contains("error:"));
}

#[test]
fn human_output_for_ingest_mentions_statuses() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .arg("ingest")
        .arg(dir.path())
        .arg("--case")
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("Hawk.log"))
        .stdout(contains("parsed"))
        .stdout(contains("not_supported"));
}
