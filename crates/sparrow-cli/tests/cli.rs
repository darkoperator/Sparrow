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
        .stdout(contains("unrecognized"));
}

#[cfg(unix)]
#[test]
fn discover_lists_unreadable_directories_as_errors() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let locked = root.join("alice@contoso.example");
    let original = std::fs::metadata(&locked).unwrap().permissions();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        std::fs::set_permissions(&locked, original).unwrap();
        eprintln!("skipping: chmod 000 directory is still readable (running as root?)");
        return;
    }
    let out = sparrow()
        .args(["--json", "discover"])
        .arg(dir.path())
        .output()
        .unwrap();
    std::fs::set_permissions(&locked, original).unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["collections"][0]["files"].as_array().unwrap();
    let e = files
        .iter()
        .find(|f| f["rel_path"] == "alice@contoso.example")
        .unwrap();
    assert!(e["artifact_id"].is_null());
    assert!(
        e["error"]
            .as_str()
            .unwrap()
            .contains("alice@contoso.example")
    );
    assert!(files.iter().any(|f| f["rel_path"] == "Hawk.log"));
}

#[test]
fn outdated_case_needs_upgrade_then_schema_works() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("old.duckdb");
    {
        let conn = duckdb::Connection::open(&case).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
        )
        .unwrap();
    }
    sparrow()
        .args(["schema", "--case"])
        .arg(&case)
        .assert()
        .code(1)
        .stderr(contains("sparrow upgrade"));
    let v = json_out(
        sparrow().args(["--json", "upgrade", "--case"]).arg(&case),
        0,
    );
    assert_eq!(v["from"], 0);
    assert!(v["to"].as_u64().unwrap() >= 2);
    sparrow()
        .args(["schema", "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("source_files"));
    sparrow()
        .args(["upgrade", "--case"])
        .arg(&case)
        .assert()
        .success();
}

#[test]
fn upgrade_refuses_to_create_a_missing_case() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("nope.duckdb");
    sparrow()
        .args(["upgrade", "--case"])
        .arg(&case)
        .assert()
        .code(1)
        .stderr(contains("not found"));
    assert!(!case.exists());
}

#[test]
fn ingest_hawk4_capture_and_verify_a_ual_record() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = dir.path().join("evidence");
    fixtures::hawk4::hawk4_tree(&evidence);
    let case = dir.path().join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&evidence)
            .arg("--case")
            .arg(&case),
        0,
    );
    let files = v["collections"][0]["files"].as_array().unwrap();
    assert!(
        files
            .iter()
            .any(|f| f["rel_path"] == fixtures::hawk4::HAWK4_PURVIEW
                && f["artifact_id"] == "portal.ual"
                && f["status"] == "parsed")
    );
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "verify",
                "ual_events",
                fixtures::ual::ID_RULE,
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(v["ok"], true);
    assert_eq!(v["sightings"].as_array().unwrap().len(), 2);
}

#[test]
fn fatal_errors_are_json_on_stdout_with_json_flag() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case)
            .args(["--culture", "xx-YY"]),
        1,
    );
    assert!(
        v["error"].as_str().unwrap().contains("unsupported culture"),
        "{v}"
    );
}

#[test]
fn ingest_of_a_folder_without_collections_does_not_create_the_case() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let case = dir.path().join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&empty)
            .arg("--case")
            .arg(&case),
        1,
    );
    assert!(v["error"].as_str().unwrap().contains("no Hawk"));
    assert!(!case.exists());
}

#[test]
fn case_inside_the_evidence_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let case = root.join("case.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(dir.path())
            .arg("--case")
            .arg(&case),
        1,
    );
    assert!(v["error"].as_str().unwrap().contains("inside the evidence"));
    assert!(!case.exists());
}

#[test]
fn schema_of_an_unknown_table_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    sparrow_core::Case::create_or_open(&case).unwrap();
    let v = json_out(
        sparrow()
            .args(["--json", "schema", "nope", "--case"])
            .arg(&case),
        1,
    );
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("no table named 'nope'")
    );
}

#[test]
fn ingest_runs_the_profile_and_profile_reruns_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    let out = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&case),
        0,
    );
    assert!(
        out["profile"]["capabilities"].as_u64().unwrap() >= 11,
        "{out}"
    );
    let out = json_out(
        sparrow().args(["--json", "profile", "--case"]).arg(&case),
        0,
    );
    assert!(out["capabilities"].as_u64().unwrap() >= 11, "{out}");
}

#[test]
fn usage_errors_exit_1_and_are_json_with_the_flag() {
    let v = json_out(sparrow().args(["--json", "ingest"]), 1);
    assert!(v["error"].as_str().unwrap().contains("required"));
    sparrow().args(["ingest"]).assert().code(1);
    sparrow().args(["--help"]).assert().success();
}
