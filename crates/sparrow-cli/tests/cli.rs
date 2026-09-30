use assert_cmd::Command;
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
    assert_eq!(v["rules"].as_array().unwrap().len(), 31);
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
    assert_eq!(expected.len(), 31, "the seed pack is 31 rules");

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
fn ioc_add_requires_an_analyst() {
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
    let add = |analyst: Option<&str>| {
        let mut c = sparrow();
        c.env_remove("SPARROW_ANALYST")
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
            .arg(&case);
        if let Some(a) = analyst {
            c.args(["--analyst", a]);
        }
        c
    };
    let v = json_out(&mut add(None), 1);
    assert!(v["error"].as_str().unwrap().contains("analyst"), "{v}");
    // The environment variable works as well.
    let v = json_out(add(None).env("SPARROW_ANALYST", "sam"), 0);
    let id = v["indicator_id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 16);
    assert!(
        json_out(&mut add(Some("   ")), 1)["error"]
            .as_str()
            .unwrap()
            .contains("analyst")
    );
    let list = json_out(
        sparrow()
            .args(["--json", "ioc", "list", "--case"])
            .arg(&case),
        0,
    );
    let items = list["indicators"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        (
            items[0]["type"].as_str(),
            items[0]["verdict"].as_str(),
            items[0]["added_by"].as_str()
        ),
        (Some("ip"), Some("malicious"), Some("analyst:sam"))
    );
    // Remove needs an analyst too.
    let rm = |analyst: Option<&str>| {
        let mut c = sparrow();
        c.env_remove("SPARROW_ANALYST")
            .args(["--json", "ioc", "remove", "--id", &id, "--case"])
            .arg(&case);
        if let Some(a) = analyst {
            c.args(["--analyst", a]);
        }
        c
    };
    json_out(&mut rm(None), 1);
    let v = json_out(&mut rm(Some("sam")), 0);
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
    // Unknown types and verdicts are usage errors.
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
                "--analyst",
                "sam",
                "--case",
            ])
            .arg(&case),
        1,
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
