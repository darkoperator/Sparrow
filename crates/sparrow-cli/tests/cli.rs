use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use serde_json::Value;
use sparrow_core::data::DataDirs;
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

#[test]
fn tenant_domains_add_list_remove() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .assert()
        .success();
    let added = json_out(
        sparrow()
            .args([
                "--json",
                "tenant",
                "domains",
                "add",
                "contoso-legacy.example",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert!(
        added["note"].as_str().is_some_and(|n| n
            .contains("identities' external/internal kind updates on the next `sparrow profile`")),
        "{added}"
    );
    let listed = json_out(
        sparrow()
            .args(["--json", "tenant", "domains", "list", "--case"])
            .arg(&case),
        0,
    );
    assert!(
        listed["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["domain"] == "contoso-legacy.example" && d["source"] == "analyst"),
        "{listed}"
    );
    let text = sparrow()
        .args([
            "tenant",
            "domains",
            "remove",
            "contoso-legacy.example",
            "--case",
        ])
        .arg(&case)
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("remove contoso-legacy.example"), "{text}");
    assert!(
        text.contains("note: tenant_domains is updated now; identities' external/internal kind updates on the next `sparrow profile`"),
        "{text}"
    );
    let listed = json_out(
        sparrow()
            .args(["--json", "tenant", "domains", "list", "--case"])
            .arg(&case),
        0,
    );
    assert!(
        !listed["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["domain"] == "contoso-legacy.example"),
        "{listed}"
    );
}

#[test]
fn capabilities_json_lists_tenants_capabilities_and_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::invictus::invictus_output_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .assert()
        .success();
    let out = json_out(
        sparrow()
            .args(["--json", "capabilities", "--case"])
            .arg(&case),
        0,
    );
    let t = &out["tenants"][0];
    assert_eq!(
        t["tenant_id"], "0e0e0e0e-0000-4000-8000-00000000000a",
        "{out}"
    );
    let ev = |id: &str| {
        t["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["evidence"] == id)
            .cloned()
            .unwrap()
    };
    assert_eq!(ev("signins")["status"], "collected", "{out}");
    assert_eq!(
        ev("users")["status"],
        "collected",
        "empty Users export: ran, nothing found: {out}"
    );
    assert_ne!(
        ev("licenses")["status"],
        "collected",
        "the Licenses folder holds only EntraSecurityDefaults (audit_config): {out}"
    );
    assert!(
        t["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "entra_id_p1")
    );

    let text = sparrow()
        .args(["capabilities", "--case"])
        .arg(&case)
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("evidence:"), "{text}");
    assert!(text.contains("signins"), "{text}");
}

#[test]
fn capabilities_without_a_profile_asks_for_one() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    drop(sparrow_core::Case::create_or_open(&case).unwrap());
    sparrow()
        .args(["capabilities", "--case"])
        .arg(&case)
        .assert()
        .failure()
        .stderr(predicates::str::contains("sparrow profile --case"));
}

#[test]
fn summary_json_reports_tenant_licences_coverage_and_gaps() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::events::hawk4_events_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .assert()
        .success();

    let out = json_out(
        sparrow().args(["--json", "summary", "--case"]).arg(&case),
        0,
    );
    let t = &out["tenants"][0];
    assert!(t["tenant_key"].as_str().is_some(), "{out}");
    assert_eq!(t["tenant_name"], "contoso_ltd", "{out}");
    assert!(
        t["licenses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "E5 (low, Hawk.log)"),
        "{out}"
    );
    assert!(!t["gaps"].as_array().unwrap().is_empty(), "{out}");
    let ual = out["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tc| tc["table"] == "ual_events")
        .unwrap();
    assert!(ual["rows"].as_i64().is_some(), "{out}");

    let text = sparrow()
        .args(["summary", "--case"])
        .arg(&case)
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("tenant "), "{text}");
    assert!(text.contains("licences:"), "{text}");
    assert!(text.contains("collections:"), "{text}");
    assert!(text.contains("coverage:"), "{text}");
    assert!(text.contains("top actors:"), "{text}");
    assert!(text.contains("gaps:"), "{text}");
}

#[test]
fn summary_without_a_profile_asks_for_one() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("case.duckdb");
    drop(sparrow_core::Case::create_or_open(&case).unwrap());
    sparrow()
        .args(["summary", "--case"])
        .arg(&case)
        .assert()
        .failure()
        .stderr(predicates::str::contains("sparrow profile --case"));
}

#[test]
fn capabilities_and_summary_warn_when_the_profile_is_stale() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::events::hawk4_events_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .assert()
        .success();
    for cmd in ["capabilities", "summary"] {
        let out = json_out(sparrow().args(["--json", cmd, "--case"]).arg(&case), 0);
        assert_eq!(out["stale"], false, "{cmd}: {out}");
        assert_eq!(
            out["stale_collections"],
            serde_json::json!([]),
            "{cmd}: {out}"
        );
    }

    // A collection loaded without a profile run (e.g. the profile failed after the ingest).
    let id: i64 = {
        let c = sparrow_core::Case::create_or_open(&case).unwrap();
        c.conn()
            .query_row(
                "INSERT INTO collections (tool, root_path, sparrow_version)
                 VALUES ('hawk', '/later', 't') RETURNING collection_id",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    for cmd in ["capabilities", "summary"] {
        let out = json_out(sparrow().args(["--json", cmd, "--case"]).arg(&case), 0);
        assert_eq!(out["stale"], true, "{cmd}: {out}");
        assert_eq!(
            out["stale_collections"],
            serde_json::json!([id]),
            "{cmd}: {out}"
        );
        assert_eq!(out["tenants"].as_array().unwrap().len(), 1, "{cmd}: {out}");

        let text = sparrow().args([cmd, "--case"]).arg(&case).output().unwrap();
        assert!(text.status.success(), "{cmd}");
        let text = String::from_utf8_lossy(&text.stdout);
        assert!(
            text.contains(&format!(
                "profile is stale: 1 collections not profiled; run `sparrow profile --case {}`",
                case.display()
            )),
            "{cmd}: {text}"
        );
        assert!(
            text.contains("tenant "),
            "{cmd}: data still printed: {text}"
        );
    }
}

#[test]
fn ingest_enriches_ips_from_geoip_dir() {
    use sparrow_core::fixtures::mmdb::{asn, city, write_mmdb};

    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::events::hawk4_events_tree(dir.path());
    let case = dir.path().join("case.duckdb");

    let geo = tempfile::tempdir().unwrap();
    let city_db = write_mmdb(
        "GeoLite2-City",
        1_790_000_000,
        &[(
            "203.0.113.0".parse().unwrap(),
            24,
            city("NG", "Nigeria", "Lagos", 6.45, 3.39),
        )],
    );
    let asn_db = write_mmdb(
        "GeoLite2-ASN",
        1_790_100_000,
        &[(
            "203.0.113.0".parse().unwrap(),
            24,
            asn(14061, "DIGITALOCEAN-ASN"),
        )],
    );
    std::fs::write(geo.path().join("GeoLite2-City.mmdb"), city_db).unwrap();
    std::fs::write(geo.path().join("GeoLite2-ASN.mmdb"), asn_db).unwrap();

    let out = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&case)
            .arg("--geoip-dir")
            .arg(geo.path()),
        0,
    );
    assert!(
        out["profile"]["ip_intel"]["geolocated"].as_u64().unwrap() > 0,
        "{out}"
    );

    let conn = duckdb::Connection::open(&case).unwrap();
    let country_iso: String = conn
        .query_row(
            "SELECT country_iso FROM ip_intel WHERE ip = '203.0.113.10'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(country_iso, "NG");
}

#[test]
fn invictus_tree_end_to_end_through_the_profile_commands() {
    use sparrow_core::fixtures::mmdb::{asn, city, write_mmdb};

    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::invictus::invictus_output_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    let geo = tempfile::tempdir().unwrap();
    let net: std::net::IpAddr = "203.0.113.0".parse().unwrap();
    std::fs::write(
        geo.path().join("GeoLite2-City.mmdb"),
        write_mmdb(
            "GeoLite2-City",
            1_790_000_000,
            &[(net, 24, city("NG", "Nigeria", "Lagos", 6.45, 3.39))],
        ),
    )
    .unwrap();
    std::fs::write(
        geo.path().join("GeoLite2-ASN.mmdb"),
        write_mmdb(
            "GeoLite2-ASN",
            1_790_100_000,
            &[(net, 24, asn(14061, "DIGITALOCEAN-ASN"))],
        ),
    )
    .unwrap();

    let ingest = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&case)
            .arg("--geoip-dir")
            .arg(geo.path()),
        0,
    );
    assert_eq!(ingest["profile"]["tenants"], 1, "{ingest}");

    let caps = json_out(
        sparrow()
            .args(["--json", "capabilities", "--case"])
            .arg(&case),
        0,
    );
    let tenant = &caps["tenants"][0];
    assert_eq!(
        tenant["tenant_key"], "0e0e0e0e-0000-4000-8000-00000000000a",
        "{caps}"
    );
    assert!(
        tenant["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "entra_id_p1" && c["status"] == "licensed"),
        "{caps}"
    );
    assert!(
        tenant["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["evidence"] == "signins" && e["status"] == "collected"),
        "{caps}"
    );

    let summary = json_out(
        sparrow().args(["--json", "summary", "--case"]).arg(&case),
        0,
    );
    assert_eq!(summary["tenants"].as_array().unwrap().len(), 1, "{summary}");

    let profile = json_out(
        sparrow()
            .args(["--json", "profile", "--case"])
            .arg(&case)
            .arg("--geoip-dir")
            .arg(geo.path()),
        0,
    );
    assert_eq!(profile["tenants"], 1, "{profile}");

    let domains = json_out(
        sparrow()
            .args(["--json", "tenant", "domains", "list", "--case"])
            .arg(&case),
        0,
    );
    assert!(
        domains["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["domain"] == "contoso.example"),
        "{domains}"
    );

    let schema = json_out(
        sparrow()
            .args(["--json", "schema", "--case"])
            .arg(&case)
            .arg("timeline"),
        0,
    );
    let tables = schema["tables"].as_array().unwrap();
    assert_eq!(tables.len(), 1, "{schema}");
    assert_eq!(tables[0]["table"], "timeline");
    assert_eq!(tables[0]["kind"], "view");
}

#[test]
fn synth_generates_then_checks_a_case() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tree");
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "synth",
                "--scenario",
                "bec-aitm",
                "--collector",
                "portal",
                "--seed",
                "4",
                "--out",
            ])
            .arg(&out),
        0,
    );
    let root = out.join(v["root"].as_str().unwrap());
    let case = dir.path().join("case.duckdb");
    sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .arg("--geoip-dir")
        .arg(out.join("geoip"))
        .assert()
        .success();
    let r = json_out(
        sparrow()
            .args(["--json", "synth", "check", "--manifest"])
            .arg(out.join("manifest.json"))
            .arg("--case")
            .arg(&case),
        0,
    );
    assert_eq!(r["ok"], true, "{r}");
}

/// The real Hawk captures hold portal exports beside the Hawk trees (survey §3), so
/// `conformance --real --collector hawk` must generate the portal collector too and compare
/// them. A stand-in real tree is a generated Hawk tree with a generated portal export beside
/// it; before the fix every portal artifact was "seen in the real tree, never generated".
#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn conformance_real_hawk_compares_portal_exports_beside_the_capture() {
    use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
    let dir = tempfile::tempdir().unwrap();
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let real = dir.path().join("real");
    let mut o = GenerateOptions::new(Collector::Hawk4, 4);
    o.ps = PsEdition::Ps7;
    sparrow_synth::generate::generate_to_dir(&scenario, &o, &real).unwrap();
    let portal = dir.path().join("portal");
    let mut o = GenerateOptions::new(Collector::Portal, 4);
    o.ps = PsEdition::Ps7;
    let m = sparrow_synth::generate::generate_to_dir(&scenario, &o, &portal).unwrap();
    std::fs::rename(portal.join(&m.root), real.join(&m.root)).unwrap();
    let v = json_out(
        sparrow()
            .args(["--json", "synth", "conformance", "--real"])
            .arg(&real)
            .args(["--collector", "hawk", "--seed", "4"]),
        0,
    );
    assert_eq!(v["ok"], true, "{v}");
}

#[test]
fn synth_rejects_unknown_scenario_and_collector() {
    let dir = tempfile::tempdir().unwrap();
    sparrow()
        .args([
            "synth",
            "--scenario",
            "nope",
            "--collector",
            "portal",
            "--out",
        ])
        .arg(dir.path().join("x"))
        .assert()
        .code(1)
        .stderr(contains("nope"));
    sparrow()
        .args([
            "synth",
            "--scenario",
            "bec-aitm",
            "--collector",
            "hawk9",
            "--out",
        ])
        .arg(dir.path().join("y"))
        .assert()
        .failure();
}

#[test]
fn synth_refuses_scale_knobs_until_they_land() {
    let dir = tempfile::tempdir().unwrap();
    sparrow()
        .args([
            "synth",
            "--scenario",
            "bec-aitm",
            "--collector",
            "portal",
            "--ual-rows",
            "10",
            "--out",
        ])
        .arg(dir.path().join("x"))
        .assert()
        .code(1)
        .stderr(contains("scale knobs"));
}

#[test]
fn synth_coverage_reports_every_rule() {
    let v = json_out(sparrow().args(["--json", "synth", "coverage"]), 0);
    assert_eq!(v["rules"].as_array().unwrap().len(), 33);
    assert_eq!(v["ok"], true);
}

fn write_rule(dir: &std::path::Path, id: &str, requires: &str) {
    let text = format!(
        "id: {id}\ntitle: custom {id}\nversion: 1\nstatus: experimental\nseverity: low\nrequires: [{requires}]\nsource: mailboxes\nmatch:\n  forwarding_smtp_address: {{exists: true}}\nanalyst_guidance: g\ntests:\n  - name: hit\n    records:\n      - table: mailboxes\n        upn: a@x.example\n        forwarding_smtp_address: e@example.net\n    expect_hits: 1\n  - name: no hit\n    records:\n      - table: mailboxes\n        upn: a@x.example\n    expect_hits: 0\n"
    );
    std::fs::create_dir_all(dir.join("custom")).unwrap();
    std::fs::write(dir.join("custom").join(format!("{id}.yaml")), text).unwrap();
}

#[test]
fn rules_lint_passes_on_builtins() {
    let v = json_out(sparrow().args(["--json", "rules", "lint"]), 0);
    let issues = v["issues"].as_array().unwrap();
    assert!(
        issues.iter().all(|i| i["severity"] != "error"),
        "{issues:#?}"
    );
    // A broken custom rule fails lint with exit 1.
    let dir = tempfile::tempdir().unwrap();
    write_rule(dir.path(), "SPW-CUS-001", "");
    let broken = std::fs::read_to_string(dir.path().join("custom/SPW-CUS-001.yaml"))
        .unwrap()
        .replace(
            "forwarding_smtp_address: {exists: true}",
            "no_such_column: {exists: true}",
        );
    std::fs::write(dir.path().join("custom/SPW-CUS-001.yaml"), broken).unwrap();
    let v = json_out(
        sparrow()
            .args(["--json", "rules", "lint", "--rules"])
            .arg(dir.path()),
        1,
    );
    assert!(
        v["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["severity"] == "error"
                && i["message"].as_str().unwrap().contains("no_such_column"))
    );
}

#[test]
fn rules_test_runs_every_inline_test() {
    let v = json_out(sparrow().args(["--json", "rules", "test"]), 0);
    let results = v["results"].as_array().unwrap();
    assert!(results.len() >= 9, "{results:#?}");
    assert!(results.iter().all(|r| r["ok"] == true), "{results:#?}");
    for id in ["SPW-HAWK-011", "SPW-ID-010", "SPW-MAIL-005"] {
        assert!(results.iter().any(|r| r["rule_id"] == id), "{id}");
    }
    let one = json_out(
        sparrow().args(["--json", "rules", "test", "--rule", "SPW-HAWK-011"]),
        0,
    );
    assert_eq!(one["results"].as_array().unwrap().len(), 2);
    // A failing inline test exits 1.
    let dir = tempfile::tempdir().unwrap();
    write_rule(dir.path(), "SPW-CUS-002", "");
    let text = std::fs::read_to_string(dir.path().join("custom/SPW-CUS-002.yaml"))
        .unwrap()
        .replace("expect_hits: 1", "expect_hits: 3");
    std::fs::write(dir.path().join("custom/SPW-CUS-002.yaml"), text).unwrap();
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "rules",
                "test",
                "--rule",
                "SPW-CUS-002",
                "--rules",
            ])
            .arg(dir.path()),
        1,
    );
    let r = &v["results"][0];
    assert_eq!(
        (r["expected"].as_u64(), r["got"].as_u64(), r["ok"].as_bool()),
        (Some(3), Some(1), Some(false))
    );
    sparrow()
        .args(["rules", "test", "--rule", "SPW-NOPE-999"])
        .assert()
        .code(1);
}

/// The seed rule pack is complete: `sparrow rules list` shows a file for every id in
/// `rules/coverage.yaml`, and `rules lint` says so too. The expected ids are derived from the
/// matrix, so a new seed rule needs no edit here -- only a file.
#[test]
fn rules_list_shows_a_file_for_every_coverage_id() {
    let cov = sparrow_core::detect::coverage::CoverageMatrix::builtin().unwrap();
    let expected: Vec<String> = cov.rules.iter().map(|r| r.id.clone()).collect();
    assert_eq!(expected.len(), 33, "the seed pack is 33 rules");

    let v = json_out(sparrow().args(["--json", "rules", "list"]), 0);
    let ids: Vec<String> = v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    let mut expected_sorted = expected.clone();
    expected_sorted.sort();
    assert_eq!(
        sorted, expected_sorted,
        "rules list does not match the coverage matrix"
    );

    // Every coverage id has a file, which is what the lint now errors on.
    let set = sparrow_core::detect::load::load_rules(&DataDirs::default()).unwrap();
    let mut loaded: Vec<String> = set.rules.iter().map(|r| r.rule.id.clone()).collect();
    loaded.sort();
    assert_eq!(loaded, expected_sorted, "a coverage id has no rule file");
}

#[test]
fn rules_list_filters_by_requires() {
    let dir = tempfile::tempdir().unwrap();
    write_rule(dir.path(), "SPW-CUS-003", "identity_protection");
    write_rule(dir.path(), "SPW-CUS-004", "");
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "rules",
                "list",
                "--requires",
                "identity_protection",
                "--rules",
            ])
            .arg(dir.path()),
        0,
    );
    let ids: Vec<&str> = v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    // The custom rule, plus every built-in whose rule file lists the capability under
    // `requires:` (derived from the files, so a new built-in needs no edit here).
    let mut expected = vec!["SPW-CUS-003".to_string()];
    expected.extend(builtin_rules_requiring("identity_protection"));
    expected.sort();
    assert_eq!(ids, expected);
    assert!(
        ids.len() > 1,
        "at least one built-in requires identity_protection"
    );
    let all = json_out(
        sparrow()
            .args(["--json", "rules", "list", "--rules"])
            .arg(dir.path()),
        0,
    );
    let ids: Vec<&str> = all["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"SPW-HAWK-011") && ids.contains(&"SPW-CUS-004"));
    let first = &all["rules"][0];
    for key in ["id", "title", "severity", "status", "requires"] {
        assert!(first.get(key).is_some(), "{key}");
    }
    let tagged = json_out(
        sparrow().args(["--json", "rules", "list", "--tag", "forwarding"]),
        0,
    );
    assert!(tagged["rules"].as_array().unwrap().iter().all(|r| {
        r["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "forwarding")
    }));
}

#[test]
fn detect_reports_per_rule_status() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&case)
            .arg("--no-detect"),
        0,
    );
    let v = json_out(sparrow().args(["--json", "detect", "--case"]).arg(&case), 0);
    let rules = v["rules"].as_array().unwrap();
    assert!(!rules.is_empty(), "{v}");
    for r in rules {
        for key in ["rule_id", "tenant_key", "status", "hits", "duration_ms"] {
            assert!(r.get(key).is_some(), "{key} in {r}");
        }
        assert!(["ran", "not_applicable", "error"].contains(&r["status"].as_str().unwrap()));
    }
    assert_eq!(v["run_id"], 1);
    let one = json_out(
        sparrow()
            .args(["--json", "detect", "--rule", "SPW-HAWK-011", "--case"])
            .arg(&case),
        0,
    );
    assert!(
        one["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["rule_id"] == "SPW-HAWK-011")
    );
    assert_eq!(one["run_id"], 2);
    // Human output names the counts.
    sparrow()
        .args(["detect", "--tag", "bec", "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("run 3"));
}

#[test]
fn ioc_add_and_remove_are_agent_writes() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::hawk_tree(dir.path());
    let case = dir.path().join("case.duckdb");
    json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&case)
            .arg("--no-detect"),
        0,
    );
    let add = |flags: &[&str]| {
        let mut c = sparrow();
        c.env_remove("SPARROW_AGENT")
            .env_remove("SPARROW_ANALYST")
            .args([
                "--json",
                "ioc",
                "add",
                "--type",
                "ip",
                "--value",
                "203.0.113.7",
                "--verdict",
                "malicious",
                "--case",
            ])
            .arg(&case)
            .args(flags);
        c
    };
    let added_by = || {
        let list = json_out(
            sparrow()
                .args(["--json", "ioc", "list", "--case"])
                .arg(&case),
            0,
        );
        let items = list["indicators"].as_array().unwrap().clone();
        assert_eq!(items.len(), 1, "{list}");
        assert_eq!(
            (items[0]["type"].as_str(), items[0]["verdict"].as_str()),
            (Some("ip"), Some("malicious"))
        );
        items[0]["added_by"].as_str().unwrap().to_string()
    };
    // No agent named: every CLI write is still an agent decision.
    let v = json_out(&mut add(&[]), 0);
    let id = v["indicator_id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 16);
    assert_eq!(v["added_by"], "agent:unnamed");
    assert_eq!(added_by(), "agent:unnamed");
    // The environment variable names the agent; --agent overrides it.
    json_out(add(&[]).env("SPARROW_AGENT", "claude"), 0);
    assert_eq!(added_by(), "agent:claude");
    json_out(add(&["--agent", "codex"]).env("SPARROW_AGENT", "claude"), 0);
    assert_eq!(added_by(), "agent:codex");
    // A blank analyst counts as none; an invalid agent id is refused before any write.
    json_out(&mut add(&["--agent", "claude", "--analyst", "   "]), 0);
    assert_eq!(added_by(), "agent:claude");
    let v = json_out(&mut add(&["--agent", "a:b"]), 1);
    assert!(v["error"].as_str().unwrap().contains("agent id"), "{v}");
    assert_eq!(added_by(), "agent:claude");
    // Remove is an agent write too.
    let v = json_out(
        sparrow()
            .env_remove("SPARROW_AGENT")
            .args([
                "--json", "ioc", "remove", "--id", &id, "--agent", "claude", "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(v["removed"], true);
    assert_eq!(
        json_out(
            sparrow()
                .args(["--json", "ioc", "list", "--case"])
                .arg(&case),
            0
        )["indicators"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    // The removed indicator stays stored (soft delete).
    let all = json_out(
        sparrow()
            .args(["--json", "ioc", "list", "--include-removed", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(all["indicators"].as_array().unwrap().len(), 1);
    assert_eq!(all["indicators"][0]["removed_by"], "agent:claude");
    // Unknown types and verdicts are invalid decisions.
    json_out(
        sparrow()
            .args([
                "--json",
                "ioc",
                "add",
                "--type",
                "nope",
                "--value",
                "x",
                "--verdict",
                "malicious",
                "--case",
            ])
            .arg(&case),
        5,
    );
}

#[test]
fn ingest_no_detect_skips_detection() {
    let dir = tempfile::tempdir().unwrap();
    let root = sparrow_core::fixtures::hawk_tree(dir.path());
    let skipped = dir.path().join("skipped.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&skipped)
            .arg("--no-detect"),
        0,
    );
    assert!(v["detect"].is_null(), "{v}");
    let ran = dir.path().join("ran.duckdb");
    let v = json_out(
        sparrow()
            .args(["--json", "ingest"])
            .arg(&root)
            .arg("--case")
            .arg(&ran),
        0,
    );
    assert!(
        v["detect"]["rules"]
            .as_array()
            .is_some_and(|r| !r.is_empty()),
        "{v}"
    );
    // `profile --no-detect` skips it as well; a plain `profile` runs it (run 2 on the ingested case).
    let v = json_out(
        sparrow()
            .args(["--json", "profile", "--no-detect", "--case"])
            .arg(&ran),
        0,
    );
    assert!(v["detect"].is_null());
    let v = json_out(sparrow().args(["--json", "profile", "--case"]).arg(&ran), 0);
    assert_eq!(v["detect"]["run_id"], 2);
    // Human output carries the detection summary.
    sparrow()
        .args(["profile", "--case"])
        .arg(&ran)
        .assert()
        .success()
        .stdout(contains("detection: run 3"));
}

/// Ids of the built-in rules (`rules/<category>/SPW-*.yaml`) whose `requires:` line names
/// `capability`.
fn builtin_rules_requiring(capability: &str) -> Vec<String> {
    fn walk(dir: &std::path::Path, capability: &str, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, capability, out);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !(name.starts_with("SPW-") && name.ends_with(".yaml")) {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let requires = text
                .lines()
                .find_map(|l| l.strip_prefix("requires:"))
                .unwrap_or("");
            if requires
                .trim_matches(|c: char| c == ' ' || c == '[' || c == ']')
                .split(',')
                .any(|c| c.trim() == capability)
            {
                out.push(name.trim_end_matches(".yaml").to_string());
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules"),
        capability,
        &mut out,
    );
    out
}

/// A fresh case file at the current schema.
fn fresh_case(dir: &std::path::Path) -> std::path::PathBuf {
    let case = dir.join("c.duckdb");
    sparrow_core::Case::create_or_open(&case).unwrap();
    case
}

/// Append `n` audit entries through core, as an agent write does.
fn audit_entries(case: &std::path::Path, n: usize) {
    let c = sparrow_core::Case::create_or_open(case).unwrap();
    let a = sparrow_core::case::actor::Actor::agent("t", Some("sam")).unwrap();
    for i in 0..n {
        c.conn().execute_batch("BEGIN TRANSACTION").unwrap();
        sparrow_core::case::audit::append(
            c.conn(),
            a.as_str(),
            a.on_behalf_of(),
            "test",
            "finding",
            &format!("f{i}"),
            None,
            Some(&serde_json::json!({ "i": i })),
            None,
        )
        .unwrap();
        c.conn().execute_batch("COMMIT").unwrap();
    }
}

#[test]
fn audit_verify_on_a_fresh_case_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let case = fresh_case(dir.path());
    let v = json_out(
        sparrow()
            .args(["--json", "audit", "verify", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(v["ok"], true);
    assert_eq!(v["entries"], 0);
    sparrow()
        .args(["audit", "verify", "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("ok"));
}

#[test]
fn audit_verify_exits_3_on_a_broken_chain_until_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let case = fresh_case(dir.path());
    audit_entries(&case, 3);
    let v = json_out(
        sparrow()
            .args(["--json", "audit", "verify", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(
        (v["ok"].as_bool(), v["entries"].as_i64()),
        (Some(true), Some(3))
    );
    let head = v["head_hash"].as_str().unwrap().to_string();
    {
        let conn = duckdb::Connection::open(&case).unwrap();
        conn.execute("DELETE FROM audit_trail WHERE seq = 2", [])
            .unwrap();
    }
    let v = json_out(
        sparrow()
            .args(["--json", "audit", "verify", "--case"])
            .arg(&case),
        3,
    );
    assert_eq!(v["ok"], false);
    assert_eq!(v["first_bad_seq"], 2);
    assert_eq!(v["head_hash"], head.as_str());
    sparrow()
        .args(["audit", "verify", "--case"])
        .arg(&case)
        .assert()
        .code(3)
        .stdout(contains("seq 2"));
    // Acknowledging records the break as an entry by the agent; the chain is usable again.
    let v = json_out(
        sparrow()
            .env_remove("SPARROW_AGENT")
            .env_remove("SPARROW_ANALYST")
            .args([
                "--json",
                "audit",
                "verify",
                "--acknowledge",
                "--agent",
                "claude",
                "--analyst",
                "sam",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(v["ok"], true);
    assert_eq!(v["acknowledged_breaks"], serde_json::json!([2]));
    let log = json_out(
        sparrow()
            .args([
                "--json",
                "audit",
                "log",
                "--object",
                "audit_trail:2",
                "--case",
            ])
            .arg(&case),
        0,
    );
    let entries = log["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{log}");
    assert_eq!(entries[0]["seq"], 4);
    assert_eq!(entries[0]["action"], "acknowledge_break");
    assert_eq!(entries[0]["actor"], "agent:claude");
    assert_eq!(entries[0]["on_behalf_of"], "analyst:sam");
    assert_eq!(entries[0]["prev_hash"], head.as_str());
}

#[test]
fn audit_log_lists_entries_and_filters_by_object() {
    let dir = tempfile::tempdir().unwrap();
    let case = fresh_case(dir.path());
    audit_entries(&case, 3);
    let v = json_out(
        sparrow()
            .args(["--json", "audit", "log", "--case"])
            .arg(&case),
        0,
    );
    let all = v["entries"].as_array().unwrap();
    assert_eq!(
        all.iter()
            .map(|e| e["seq"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(all[0]["actor"], "agent:t");
    assert_eq!(all[0]["on_behalf_of"], "analyst:sam");
    assert!(all[0]["ts"].as_str().unwrap().ends_with('Z'));
    let v = json_out(
        sparrow()
            .args(["--json", "audit", "log", "--object", "finding:f1", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    assert_eq!(v["entries"][0]["seq"], 2);
    sparrow()
        .args(["audit", "log", "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("agent:t for analyst:sam test finding:f1"));
    // An --object without TYPE:ID is a usage error.
    json_out(
        sparrow()
            .args(["--json", "audit", "log", "--object", "f1", "--case"])
            .arg(&case),
        1,
    );
}

#[test]
fn ioc_add_records_agent_and_on_behalf_of() {
    let dir = tempfile::tempdir().unwrap();
    let case = fresh_case(dir.path());
    sparrow()
        .args([
            "ioc",
            "add",
            "--type",
            "ip",
            "--value",
            "203.0.113.9",
            "--verdict",
            "malicious",
            "--agent",
            "claude",
            "--analyst",
            "carlos",
            "--case",
        ])
        .arg(&case)
        .assert()
        .success();
    let v = json_out(
        sparrow()
            .args(["--json", "audit", "log", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(v["entries"][0]["actor"], "agent:claude");
    assert_eq!(v["entries"][0]["on_behalf_of"], "analyst:carlos");
    assert_eq!(v["entries"][0]["action"], "add_ioc");
    let list = json_out(
        sparrow()
            .args(["--json", "ioc", "list", "--case"])
            .arg(&case),
        0,
    );
    let i = &list["indicators"][0];
    assert_eq!(
        (&i["decided_by"], &i["on_behalf_of"], &i["review_state"]),
        (
            &serde_json::json!("agent:claude"),
            &serde_json::json!("analyst:carlos"),
            &serde_json::json!("pending_review")
        )
    );
}

#[test]
fn second_writer_process_is_refused_and_chain_stays_linear() {
    let dir = tempfile::tempdir().unwrap();
    let case = fresh_case(dir.path());
    audit_entries(&case, 1);
    let first = sparrow_core::Case::create_or_open(&case).unwrap();
    for args in [
        vec![
            "--json",
            "ioc",
            "add",
            "--type",
            "ip",
            "--value",
            "203.0.113.9",
            "--verdict",
            "malicious",
            "--case",
        ],
        vec!["--json", "audit", "verify", "--acknowledge", "--case"],
        vec!["--json", "upgrade", "--case"],
    ] {
        let v = json_out(sparrow().args(&args).arg(&case), 4);
        assert!(
            v["error"].as_str().unwrap().contains("another writer"),
            "{args:?}: {v}"
        );
    }
    drop(first);
    let v = json_out(
        sparrow()
            .args(["--json", "audit", "verify", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(
        (v["ok"].as_bool(), v["entries"].as_i64()),
        (Some(true), Some(1))
    );
    let v = json_out(
        sparrow()
            .args(["--json", "ioc", "list", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(v["indicators"].as_array().unwrap().len(), 0);
}

/// A fresh case with one rule finding, `f1`.
fn case_with_finding(dir: &std::path::Path) -> std::path::PathBuf {
    let case = fresh_case(dir);
    let conn = duckdb::Connection::open(&case).unwrap();
    conn.execute_batch(
        "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
         title, created_by, created_at, updated_at) \
         VALUES ('f1', 'fp1', 't1', 'SPW-ID-004', 1, 'x', 'high', 'AiTM', 'rule', now(), now());",
    )
    .unwrap();
    case
}

fn finding_row(
    case: &std::path::Path,
) -> (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let conn = duckdb::Connection::open(case).unwrap();
    conn.query_row(
        "SELECT CAST(status AS VARCHAR), disposition_reason, decided_by, on_behalf_of, CAST(review_state AS VARCHAR) \
         FROM findings",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )
    .unwrap()
}

#[test]
fn finding_writes_are_agent_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_finding(dir.path());
    let v = json_out(
        sparrow()
            .env_remove("SPARROW_AGENT")
            .env_remove("SPARROW_ANALYST")
            .args([
                "--json",
                "finding",
                "set-status",
                "f1",
                "confirmed",
                "--reason",
                "token replay",
                "--agent",
                "claude",
                "--analyst",
                "carlos",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(v["action"], "set_status");
    assert_eq!(v["seq"], 1);
    assert_eq!(v["after"]["status"], "confirmed");
    assert_eq!(
        finding_row(&case),
        (
            "confirmed".into(),
            Some("token replay".into()),
            Some("agent:claude".into()),
            Some("analyst:carlos".into()),
            Some("pending_review".into())
        )
    );
    sparrow()
        .env("SPARROW_AGENT", "codex")
        .env_remove("SPARROW_ANALYST")
        .args(["finding", "assign", "f1", "dana", "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains(
            "f1 assigned to dana (decided by agent:codex, pending review)",
        ));
    // Nothing to acknowledge: an invalid decision, exit 5, nothing written.
    let v = json_out(
        sparrow()
            .args(["--json", "finding", "ack-rule-update", "f1", "--case"])
            .arg(&case),
        5,
    );
    assert!(
        v["error"].as_str().unwrap().contains("no rule update"),
        "{v}"
    );
    let log = json_out(
        sparrow()
            .args(["--json", "audit", "log", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(log["entries"].as_array().unwrap().len(), 2);
}

#[test]
fn invalid_decisions_exit_5_and_write_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_finding(dir.path());
    for args in [
        vec!["finding", "set-status", "f1", "closed"],
        vec!["finding", "set-status", "f1", "false_positive"],
        vec!["finding", "set-status", "f1", "benign", "--reason", "  "],
        vec!["finding", "set-status", "nope", "in_review"],
        vec!["finding", "assign", "nope", "dana"],
        vec!["ioc", "set-verdict", "--id", "nope", "--verdict", "benign"],
        vec![
            "ioc",
            "add",
            "--type",
            "ip",
            "--value",
            "1.2.3.4",
            "--verdict",
            "bad",
        ],
    ] {
        let v = json_out(
            sparrow().arg("--json").args(&args).arg("--case").arg(&case),
            5,
        );
        assert!(v["error"].is_string(), "{args:?}: {v}");
    }
    assert_eq!(finding_row(&case).0, "new");
    let log = json_out(
        sparrow()
            .args(["--json", "audit", "log", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(log["entries"].as_array().unwrap().len(), 0);
}

#[test]
fn a_write_on_a_broken_chain_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_finding(dir.path());
    json_out(
        sparrow()
            .args([
                "--json",
                "finding",
                "set-status",
                "f1",
                "in_review",
                "--case",
            ])
            .arg(&case),
        0,
    );
    {
        let conn = duckdb::Connection::open(&case).unwrap();
        conn.execute("UPDATE audit_trail SET actor = 'x'", [])
            .unwrap();
    }
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "finding",
                "set-status",
                "f1",
                "needs_more_data",
                "--case",
            ])
            .arg(&case),
        3,
    );
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("audit chain is broken"),
        "{v}"
    );
    assert_eq!(finding_row(&case).0, "in_review");
}

/// A fresh case with provenance for signins:k1 and ual_events:a:b.
fn case_with_evidence(dir: &std::path::Path) -> std::path::PathBuf {
    let case = fresh_case(dir);
    let conn = duckdb::Connection::open(&case).unwrap();
    conn.execute_batch(
        "INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) VALUES ('invictus', '/e', 't', 't1');
         INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status) VALUES (1, 's.json', 9, 'aa', 'parsed');
         INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end, byte_offset,
                                     byte_length, raw_sha256) VALUES
             ('signins', 'k1', 1, 0, 1, 1, 0, 5, 'r1'), ('ual_events', 'a:b', 1, 1, 2, 2, 5, 4, 'r2');",
    )
    .unwrap();
    case
}

#[test]
fn timeline_entries_and_notes_are_agent_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_evidence(dir.path());
    let run = |args: &[&str], code: i32| {
        json_out(
            sparrow()
                .env_remove("SPARROW_AGENT")
                .env_remove("SPARROW_ANALYST")
                .arg("--json")
                .args(args)
                .args(["--agent", "claude", "--analyst", "carlos", "--case"])
                .arg(&case),
            code,
        )
    };
    let p = run(
        &[
            "timeline-entry",
            "propose",
            "--time",
            "2026-08-03T09:00:00Z",
            "--title",
            "AiTM sign-in",
            "--narrative",
            "replayed session",
            "--phase",
            "initial_access",
            "--evidence",
            "signins:k1",
            "--evidence",
            "ual_events:a:b",
            "--tenant",
            "t1",
        ],
        0,
    );
    assert_eq!(p["action"], "propose_entry");
    assert_eq!(p["actor"], "agent:claude");
    assert_eq!(p["on_behalf_of"], "analyst:carlos");
    assert_eq!(
        p["after"]["evidence"],
        serde_json::json!(["signins:k1", "ual_events:a:b"])
    );
    let id = p["object_id"].as_str().unwrap().to_string();
    let v = run(&["timeline-entry", "verify", &id], 0);
    assert_eq!(v["after"]["status"], "verified");
    // Editing the verified entry proposes a successor.
    let e = run(
        &[
            "timeline-entry",
            "edit",
            &id,
            "--title",
            "AiTM sign-in from a VPS",
        ],
        0,
    );
    assert_eq!(e["action"], "propose_entry");
    let new_id = e["object_id"].as_str().unwrap().to_string();
    assert_ne!(new_id, id);
    assert_eq!(e["after"]["supersedes"], id.as_str());
    let r = run(
        &[
            "timeline-entry",
            "reject",
            &new_id,
            "--reason",
            "keep the first",
        ],
        0,
    );
    assert_eq!(r["reason"], "keep the first");
    let n = run(
        &[
            "note",
            "add",
            &format!("entry:{id}"),
            "--text",
            "a,b\"c\nd|e 🔥",
        ],
        0,
    );
    assert_eq!(
        (n["action"].as_str(), n["after"]["text"].as_str()),
        (Some("add_note"), Some("a,b\"c\nd|e 🔥"))
    );
    run(&["note", "add", "ual_events:a:b", "--text", "seen"], 0);
    sparrow()
        .args(["timeline-entry", "verify", &new_id, "--case"])
        .arg(&case)
        .assert()
        .code(5);
    let log = json_out(
        sparrow()
            .args(["--json", "audit", "log", "--case"])
            .arg(&case),
        0,
    );
    let actions: Vec<&str> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        [
            "propose_entry",
            "verify_entry",
            "propose_entry",
            "reject_entry",
            "add_note",
            "add_note"
        ]
    );
}

#[test]
fn invalid_timeline_and_note_input_exits_5_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_evidence(dir.path());
    for args in [
        vec![
            "timeline-entry",
            "propose",
            "--time",
            "yesterday",
            "--title",
            "t",
            "--phase",
            "recon",
        ],
        vec![
            "timeline-entry",
            "propose",
            "--time",
            "2026-08-03T09:00:00Z",
            "--title",
            "t",
            "--phase",
            "lateral",
        ],
        vec![
            "timeline-entry",
            "propose",
            "--time",
            "2026-08-03T09:00:00Z",
            "--title",
            "t",
            "--phase",
            "recon",
            "--evidence",
            "signins:nope",
        ],
        vec![
            "timeline-entry",
            "propose",
            "--time",
            "2026-08-03T09:00:00Z",
            "--title",
            "t",
            "--phase",
            "recon",
            "--evidence",
            "nocolon",
        ],
        vec!["timeline-entry", "verify", "nope"],
        vec!["timeline-entry", "reject", "nope", "--reason", "x"],
        vec!["note", "add", "finding:nope", "--text", "x"],
        vec!["note", "add", "signins:k1", "--text", "  "],
    ] {
        let v = json_out(
            sparrow().arg("--json").args(&args).arg("--case").arg(&case),
            5,
        );
        assert!(v["error"].is_string(), "{args:?}: {v}");
    }
    let log = json_out(
        sparrow()
            .args(["--json", "audit", "log", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(log["entries"].as_array().unwrap().len(), 0);
}

#[test]
fn audit_verify_detects_and_acknowledges_a_truncated_chain() {
    let dir = tempfile::tempdir().unwrap();
    let case = fresh_case(dir.path());
    audit_entries(&case, 3);
    {
        let conn = duckdb::Connection::open(&case).unwrap();
        conn.execute("DELETE FROM audit_trail WHERE seq = 3", [])
            .unwrap();
    }
    let v = json_out(
        sparrow()
            .args(["--json", "audit", "verify", "--case"])
            .arg(&case),
        3,
    );
    assert_eq!(v["first_bad_seq"], 3);
    assert_eq!(
        v["problem"],
        "chain is shorter than the recorded head (seq 3)"
    );
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "audit",
                "verify",
                "--acknowledge",
                "--agent",
                "claude",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(v["acknowledged_breaks"], serde_json::json!([3]));
    audit_entries(&case, 1);
    json_out(
        sparrow()
            .args(["--json", "audit", "verify", "--case"])
            .arg(&case),
        0,
    );
}

#[test]
fn plain_output_escapes_control_characters_and_narratives_can_be_cleared() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_evidence(dir.path());
    // An ESC in agent text never reaches the terminal raw.
    let out = sparrow()
        .args([
            "ioc",
            "add",
            "--type",
            "domain",
            "--value",
            "evil\u{1b}[2J.example",
            "--verdict",
            "malicious",
            "--note",
        ])
        .arg("x\u{7}y")
        .arg("--case")
        .arg(&case)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains("evil\\u{001B}[2J.example"), "{text:?}");
    let out = sparrow()
        .args(["ioc", "list", "--case"])
        .arg(&case)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{7}'),
        "{text:?}"
    );
    assert!(text.contains("x\\u{0007}y"), "{text:?}");
    // The stored value is untouched.
    let v = json_out(
        sparrow()
            .args(["--json", "ioc", "list", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(v["indicators"][0]["value"], "evil\u{1b}[2J.example");
    // --clear-narrative removes it and conflicts with --narrative.
    let p = json_out(
        sparrow()
            .args([
                "--json",
                "timeline-entry",
                "propose",
                "--time",
                "2026-08-03T09:00:00Z",
                "--title",
                "t",
                "--phase",
                "recon",
                "--narrative",
                "n",
                "--case",
            ])
            .arg(&case),
        0,
    );
    let id = p["object_id"].as_str().unwrap().to_string();
    sparrow()
        .args([
            "timeline-entry",
            "edit",
            &id,
            "--clear-narrative",
            "--narrative",
            "x",
            "--case",
        ])
        .arg(&case)
        .assert()
        .failure();
    let e = json_out(
        sparrow()
            .args([
                "--json",
                "timeline-entry",
                "edit",
                &id,
                "--clear-narrative",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(e["before"]["narrative"], "n");
    assert!(e["after"]["narrative"].is_null());
    // Over-long text is an invalid decision.
    let long = "x".repeat(16 * 1024 + 1);
    json_out(
        sparrow()
            .args([
                "--json",
                "note",
                "add",
                "signins:k1",
                "--text",
                &long,
                "--case",
            ])
            .arg(&case),
        5,
    );
}

/// Synthetic bec-aitm (Invictus), generated, ingested and detected through the binary.
fn ingested(dir: &std::path::Path) -> std::path::PathBuf {
    let out = dir.join("tree");
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "synth",
                "--scenario",
                "bec-aitm",
                "--collector",
                "invictus",
                "--seed",
                "4",
                "--out",
            ])
            .arg(&out),
        0,
    );
    let root = out.join(v["root"].as_str().unwrap());
    let case = dir.join("case.duckdb");
    // 2 = completed with file problems (the generated tree's deliberate edge cases); the case is complete.
    let code = sparrow()
        .args(["ingest"])
        .arg(&root)
        .arg("--case")
        .arg(&case)
        .arg("--geoip-dir")
        .arg(out.join("geoip"))
        .output()
        .unwrap()
        .status
        .code();
    assert!(matches!(code, Some(0) | Some(2)), "{code:?}");
    case
}

#[test]
fn read_commands_report_and_cap() {
    let dir = tempfile::tempdir().unwrap();
    let case = ingested(dir.path());
    let (total, user, ip): (i64, String, String) = {
        let c = sparrow_core::Case::open_read_only(&case).unwrap();
        let t = c
            .conn()
            .query_row("SELECT count(*) FROM timeline", [], |r| r.get(0))
            .unwrap();
        let u = c
            .conn()
            .query_row(
                "SELECT actor_upn FROM timeline WHERE actor_upn LIKE '%@%' GROUP BY actor_upn ORDER BY count(*) DESC, 1 LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let i = c
            .conn()
            .query_row(
                "SELECT ip FROM timeline WHERE ip IS NOT NULL GROUP BY ip ORDER BY count(*) DESC, 1 LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (t, u, i)
    };
    assert!(total > 3, "{total}");
    let v = json_out(
        sparrow()
            .args(["--json", "timeline", "--limit", "3", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(v["rows"].as_array().unwrap().len(), 3);
    assert_eq!(
        (v["total"].as_i64(), v["truncated"].as_bool()),
        (Some(total), Some(true))
    );
    sparrow()
        .args(["timeline", "--limit", "3", "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains(format!("… {} more (truncated)", total - 3)));
    let v = json_out(
        sparrow()
            .args([
                "--json", "timeline", "--user", &user, "--limit", "100000", "--case",
            ])
            .arg(&case),
        0,
    );
    assert!(v["total"].as_i64().unwrap() > 0);
    assert!(
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["actor_upn"] == user.as_str() || r["target"] == user.as_str())
    );
    let findings = json_out(
        sparrow()
            .args(["--json", "finding", "list", "--case"])
            .arg(&case),
        0,
    );
    let list = findings["findings"].as_array().unwrap();
    assert!(!list.is_empty(), "bec-aitm raises findings");
    let id = list[0]["finding_id"].as_str().unwrap();
    let s = json_out(
        sparrow()
            .args(["--json", "finding", "show", id, "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(s["finding"]["finding_id"], id);
    assert!(!s["evidence"].as_array().unwrap().is_empty());
    assert!(
        s["analyst_guidance"]
            .as_str()
            .is_some_and(|g| !g.trim().is_empty())
    );
    sparrow()
        .args(["finding", "show", id, "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("evidence ("));
    let p = json_out(
        sparrow()
            .args(["--json", "pivot", "user", &user, "--cap", "1", "--case"])
            .arg(&case),
        0,
    );
    let sections = p["sections"].as_array().unwrap();
    let names: Vec<&str> = sections
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "identity",
            "directory",
            "roles",
            "mfa",
            "timeline",
            "findings",
            "indicators"
        ]
    );
    assert!(
        sections
            .iter()
            .all(|s| s["rows"].as_array().unwrap().len() <= 1)
    );
    let tl = sections.iter().find(|s| s["name"] == "timeline").unwrap();
    assert_eq!(tl["truncated"], true);
    let p = json_out(
        sparrow()
            .args(["--json", "pivot", "ip", &ip, "--case"])
            .arg(&case),
        0,
    );
    assert!(p["sections"][2]["total"].as_i64().unwrap() > 0);
    sparrow()
        .args(["pivot", "user", &user, "--cap", "1", "--case"])
        .arg(&case)
        .assert()
        .success()
        .stdout(contains("== timeline (").and(contains("more (truncated)")));
    let q = json_out(
        sparrow()
            .args([
                "--json",
                "query",
                "SELECT count(*) AS n FROM timeline",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(q["columns"], serde_json::json!(["n"]));
    assert_eq!(q["rows"][0][0], total);
    let q = json_out(
        sparrow()
            .args(["--json", "query", "DELETE FROM findings", "--case"])
            .arg(&case),
        1,
    );
    assert!(q["error"].as_str().unwrap().contains("SELECT"), "{q}");
    let after = json_out(
        sparrow()
            .args(["--json", "finding", "list", "--case"])
            .arg(&case),
        0,
    );
    assert_eq!(after["findings"].as_array().unwrap().len(), list.len());
    json_out(
        sparrow()
            .args(["--json", "finding", "list", "--status", "closed", "--case"])
            .arg(&case),
        5,
    );
}

#[test]
fn read_commands_while_another_process_writes_exit_4() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_finding(dir.path());
    let writer = sparrow_core::Case::create_or_open(&case).unwrap();
    for args in [
        vec!["--json", "finding", "list", "--case"],
        vec!["--json", "timeline", "--case"],
        vec!["--json", "audit", "verify", "--case"],
        vec!["--json", "query", "SELECT 1", "--case"],
    ] {
        let v = json_out(sparrow().args(&args).arg(&case), 4);
        assert!(
            v["error"].as_str().unwrap().contains("another writer"),
            "{args:?}: {v}"
        );
    }
    drop(writer);
    json_out(
        sparrow()
            .args(["--json", "finding", "list", "--case"])
            .arg(&case),
        0,
    );
}

#[test]
fn timeline_entry_list_escapes_agent_text() {
    let dir = tempfile::tempdir().unwrap();
    let case = case_with_evidence(dir.path());
    json_out(
        sparrow()
            .args([
                "--json",
                "timeline-entry",
                "propose",
                "--time",
                "2026-08-03T09:00:00Z",
                "--title",
                "evil\u{1b}[2Jtitle",
                "--phase",
                "recon",
                "--evidence",
                "signins:k1",
                "--case",
            ])
            .arg(&case),
        0,
    );
    let out = sparrow()
        .args(["timeline-entry", "list", "--case"])
        .arg(&case)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        !text.contains('\u{1b}') && text.contains("evil\\u{001B}[2Jtitle"),
        "{text:?}"
    );
    assert!(text.contains("1 entries"));
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "timeline-entry",
                "list",
                "--status",
                "proposed",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(v["entries"][0]["title"], "evil\u{1b}[2Jtitle");
    assert_eq!(v["entries"][0]["evidence"][0]["record_key"], "k1");
    let v = json_out(
        sparrow()
            .args([
                "--json",
                "timeline-entry",
                "list",
                "--status",
                "verified",
                "--case",
            ])
            .arg(&case),
        0,
    );
    assert_eq!(v["entries"].as_array().unwrap().len(), 0);
}
