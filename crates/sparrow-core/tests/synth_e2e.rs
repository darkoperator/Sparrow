//! Task 27: end-to-end tests on generated trees. Replaces the five scenario-level e2e files
//! (`ual_e2e`, `state_e2e`, `events_e2e`, `invictus_e2e`, `profile_e2e`): every built-in
//! scenario × collector is generated, ingested, profiled and compared with its manifest. The
//! hand-written fixture trees stay for the narrow parser/state tests.
//!
//! Generated trees are cached per `(scenario, options)` and re-ingested into a fresh `Case` by
//! each test, so the expensive generation runs once.

#[path = "common/synth.rs"]
mod synth;

use chrono::{DateTime, Duration, Utc};
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::discovery::Tool;
use sparrow_core::discovery::discover_collections;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileStatus, IngestOptions, ingest_collections, ingest_path};
use sparrow_core::profile::availability::EVIDENCE;
use sparrow_core::profile::{ProfileOptions, refresh};
use sparrow_core::verify::verify_record;
use sparrow_synth::cache::{Cache, CachedTree, Stage};
use sparrow_synth::check::check;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::manifest::Manifest;
use sparrow_synth::options::{
    Collector, Culture, GenerateOptions, PsEdition, SigninExport, UalFormat,
};
use sparrow_synth::scenario::{At, Scenario, StoryKind, StorySpec, builtin_names, load};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use uuid::Uuid;

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// The distinct keys of `table` as Sparrow stores them (`check`'s key expression).
fn table_keys(case: &Case, table: &str) -> std::collections::BTreeSet<String> {
    let expr = if table == "ual_events" {
        "lower(CAST(record_id AS VARCHAR))"
    } else {
        "record_key"
    };
    let mut stmt = case
        .conn()
        .prepare(&format!("SELECT DISTINCT {expr} FROM {table}"))
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// The manifest's `keys_sha256` scheme: SHA-256 of the sorted unique keys joined by `\n`.
fn keys_sha256(keys: &std::collections::BTreeSet<String>) -> String {
    use sha2::{Digest, Sha256};
    let joined = keys
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    hex::encode(Sha256::digest(joined.as_bytes()))
}

/// `case`'s key set for `table` matches the manifest: the listed keys, or (above 5000) the hash.
fn assert_keys_match_manifest(case: &Case, m: &Manifest, table: &str) {
    let e = &m.tables[table];
    let keys = table_keys(case, table);
    if !e.keys.is_empty() {
        let expected: std::collections::BTreeSet<String> = e.keys.iter().cloned().collect();
        assert_eq!(keys, expected, "{table} keys");
    } else if let Some(h) = &e.keys_sha256 {
        assert_eq!(keys_sha256(&keys), *h, "{table} key hash");
    }
    assert_eq!(keys.len() as u64, e.rows, "{table} key count");
}

/// Ingest one cached tree into an existing case (no profile).
fn ingest_into(case: &mut Case, g: &Generated) {
    let report = ingest_path(
        case,
        &g.dir,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    no_error_files(&report);
}

/// Ingest one cached tree into a fresh case (no profile); for key-set checks.
fn ingest_tree(g: &Generated) -> Case {
    let mut case = Case::in_memory().unwrap();
    ingest_into(&mut case, g);
    case
}

/// One generated tree: the parent dir that holds `<manifest.root>` and the manifest. The tree
/// and the pristine ingested cases come from the cross-binary test cache (`sparrow_synth::cache`);
/// every `profiled()` / `detected()` call is a private copy.
struct Generated {
    /// Keeps a private (uncached) tree alive for the life of the value.
    _tree: CachedTree,
    dir: PathBuf,
    manifest: Manifest,
    scenario: Scenario,
    opts: GenerateOptions,
}

static TEST_CACHE: LazyLock<Cache> = LazyLock::new(|| sparrow_synth::test_cache!());

impl Generated {
    fn case(&self, stage: Stage) -> Case {
        TEST_CACHE
            .case(&self.scenario, &self.opts, stage)
            .unwrap_or_else(|e| panic!("cached case: {e}"))
            .case
    }

    /// A private, ingested and profiled copy (what `ingest_generated` returned).
    fn profiled(&self) -> Case {
        self.case(Stage::Profiled)
    }

    /// A private, ingested, profiled and detected copy (`ingest_generated_detected`).
    fn detected(&self) -> Case {
        self.case(Stage::Detected)
    }
}

static CACHE: LazyLock<Mutex<BTreeMap<String, Arc<Generated>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Generate `scenario` once per option set and cache it for the rest of the process. `label`
/// distinguishes a modified scenario from the built-in one it was cloned from.
fn generated(label: &str, scenario: &Scenario, opts: &GenerateOptions) -> Arc<Generated> {
    let key = format!("{label}|{opts:?}");
    if let Some(g) = CACHE.lock().unwrap().get(&key) {
        return g.clone();
    }
    let tree = TEST_CACHE
        .tree(scenario, opts)
        .unwrap_or_else(|e| panic!("cached tree: {e}"));
    let g = Arc::new(Generated {
        dir: tree.dir.clone(),
        manifest: tree.manifest.clone(),
        _tree: tree,
        scenario: scenario.clone(),
        opts: opts.clone(),
    });
    CACHE.lock().unwrap().insert(key, g.clone());
    g
}

/// The built-in scenario `name` generated with `opts`, cached.
fn builtin(name: &str, opts: &GenerateOptions) -> Arc<Generated> {
    generated(name, &load(name).unwrap(), opts)
}

/// Generate `name` for `opts`, ingest, profile and detect it, and `check` it against its
/// manifest, the exact detection gate included.
fn checked(name: &str, opts: &GenerateOptions) {
    let g = builtin(name, opts);
    let r = check(&g.manifest, &g.detected()).unwrap();
    assert!(
        r.ok,
        "{name} {:?} seed {}: {:#?}",
        opts.collector, opts.seed, r.problems
    );
    assert!(
        r.detection.skipped.is_none() && r.detection.rules_checked > 0,
        "{name} {:?}: the detection gate did not run: {:?}",
        opts.collector,
        r.detection
    );
}

/// Fast representative of the every-scenario matrix below: bec-aitm for each collector.
#[test]
fn bec_aitm_checks_green_for_every_collector() {
    for c in Collector::ALL {
        checked("bec-aitm", &GenerateOptions::new(*c, 1));
    }
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn every_builtin_scenario_and_collector_checks_green() {
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            checked(name, &GenerateOptions::new(*c, 1));
        }
    }
    // Day-first culture and PS 5.1 for the Microsoft-Extractor-Suite writer.
    let mut de = GenerateOptions::new(Collector::Invictus, 1);
    de.ps = PsEdition::Ps51;
    de.culture = Culture::DeDe;
    checked("bec-aitm", &de);
    // Hawk 4 mixed editions on a non-Windows host (literal `\Tenant`, LF line ends).
    let mut mixed = GenerateOptions::new(Collector::Hawk4, 1);
    mixed.hawk_mixed_editions = true;
    mixed.non_windows = true;
    checked("hawk-investigate", &mixed);
}

/// Every storyline record (of every collector) re-verifies against the generated file it was
/// written into: the record lines/sighting in `record_sources` and the raw record bytes.
fn verify_storyline_records(c: Collector, opts: &GenerateOptions) {
    let g = builtin("bec-aitm", opts);
    let case = g.profiled();
    // Resolve each distinct delivered record once (one record can have many sightings).
    let mut records: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    for s in &g.manifest.storylines {
        for e in &s.evidence {
            for landed in &e.delivered {
                let sighting = &landed.sighting;
                let key: String = case
                    .conn()
                    .query_row(
                        "SELECT rs.record_key FROM record_sources rs
                         JOIN source_files sf USING (file_id)
                         WHERE rs.table_name = ? AND sf.rel_path = ?
                           AND rs.line_start = ? AND rs.line_end = ?",
                        duckdb::params![
                            landed.table,
                            sighting.rel_path,
                            sighting.line_start as i64,
                            sighting.line_end as i64
                        ],
                        |r| r.get(0),
                    )
                    .unwrap();
                records.insert((landed.table.clone(), key));
            }
        }
    }
    for (table, key) in &records {
        let v = verify_record(&case, table, key, None).unwrap();
        assert!(v.ok, "{c:?} {table} {key}: {v:?}");
    }
    assert!(
        records.len() > 10,
        "{c:?}: only {} storyline records verified",
        records.len()
    );
}

/// Default-job representative: Hawk 4.0 on PowerShell 7.
#[test]
fn storyline_records_verify_against_the_original_files_for_hawk4() {
    let mut o = GenerateOptions::new(Collector::Hawk4, 1);
    o.ps = PsEdition::Ps7;
    verify_storyline_records(Collector::Hawk4, &o);
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn storyline_records_verify_against_the_original_files() {
    for c in Collector::ALL {
        verify_storyline_records(*c, &GenerateOptions::new(*c, 1));
    }
}

/// Every flag that names a case table points at a row that exists.
fn assert_flags_resolve(case: &Case) {
    for table in [
        "inbox_rules",
        "oauth_grants",
        "risky_users",
        "risk_detections",
        "mobile_devices",
        "role_assignments",
        "admin_audit_events",
        "signins",
        "ual_events",
    ] {
        let key = if table == "ual_events" {
            "CAST(record_id AS VARCHAR)".to_string()
        } else {
            "record_key".to_string()
        };
        let bad: Vec<String> = {
            let mut stmt = case
                .conn()
                .prepare(&format!(
                    "SELECT linked_key FROM collector_flags
                     WHERE linked_table = '{table}' AND linked_key NOT IN (SELECT {key} FROM {table})"
                ))
                .unwrap();
            stmt.query_map([], |r| r.get::<_, Option<String>>(0))
                .unwrap()
                .filter_map(Result::unwrap)
                .collect()
        };
        assert!(bad.is_empty(), "{table} flags do not resolve: {bad:?}");
    }
    // A `_Investigate.txt` reference carries the file path; the on-demand IP-folder files are
    // referenced by file name, so accept either the exact rel_path or a trailing match.
    let bad: Vec<String> = {
        let mut stmt = case
            .conn()
            .prepare(
                "SELECT cf.linked_key FROM collector_flags cf
                 WHERE cf.linked_table = 'source_files' AND cf.linked_key IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM source_files sf
                                   WHERE sf.rel_path = cf.linked_key
                                      OR sf.rel_path LIKE '%/' || cf.linked_key)",
            )
            .unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert!(bad.is_empty(), "source_files flags do not resolve: {bad:?}");
}

/// Hawk `_Investigate_` flags link to the records the tree holds (state and event tables).
#[test]
fn collector_flags_link_to_their_records() {
    for c in [Collector::Hawk4, Collector::Hawk3] {
        let g = builtin("bec-aitm", &GenerateOptions::new(c, 1));
        let case = g.profiled();
        assert!(
            count(&case, "SELECT count(*) FROM collector_flags") > 0,
            "{c:?}: no flags"
        );
        assert_flags_resolve(&case);
    }
}

/// Values of `column` in every CSV file of `artifact`, read with Sparrow's own CSV reader, so a
/// quoted field containing a comma stays one value (a hand-split line would shift the column).
fn csv_column(g: &Generated, artifact: &str, column: &str) -> Vec<String> {
    let mut out = Vec::new();
    for f in g
        .manifest
        .files
        .iter()
        .filter(|f| f.artifact_id.as_deref() == Some(artifact))
    {
        let path = g.dir.join(&g.manifest.root).join(&f.rel_path);
        if path.extension().and_then(|e| e.to_str()) != Some("csv") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let table = sparrow_core::readers::csv_scan::read_csv(&text);
        let Some(index) = table.headers.iter().position(|h| h == column) else {
            continue;
        };
        out.extend(table.rows.iter().map(|r| r.fields[index].clone()));
    }
    assert!(
        !out.is_empty(),
        "{artifact}: no CSV rows in column {column}"
    );
    out
}

/// Every non-null value of one column of a case table.
fn db_column(case: &Case, table: &str, column: &str) -> Vec<String> {
    let mut stmt = case
        .conn()
        .prepare(&format!(
            "SELECT {column} FROM {table} WHERE {column} IS NOT NULL"
        ))
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Values of `key` in every JSON-array file of `artifact`, parsed with `serde_json` (the
/// `ConvertTo-Json` counterpart of `csv_column`).
fn json_column(g: &Generated, artifact: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for f in g
        .manifest
        .files
        .iter()
        .filter(|f| f.artifact_id.as_deref() == Some(artifact))
    {
        let path = g.dir.join(&g.manifest.root).join(&f.rel_path);
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        for row in value.as_array().into_iter().flatten() {
            if let Some(s) = row.get(key).and_then(serde_json::Value::as_str) {
                out.push(s.to_string());
            }
        }
    }
    assert!(!out.is_empty(), "{artifact}: no JSON rows with {key}");
    out
}

/// Some directory users' `displayName` is "Last, First" (world users 2 and 5). Every collector's
/// CSV export must quote the comma, and every parser must load the exact name.
#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn comma_display_names_load_exactly_per_collector() {
    let world = sparrow_synth::world::World::build(&load("bec-aitm").unwrap(), 1).unwrap();
    let expected: Vec<String> = [2u32, 5]
        .iter()
        .map(|n| world.user(*n).display_name.clone())
        .collect();
    assert!(expected.iter().all(|n| n.contains(", ")), "{expected:?}");

    // (artifact, collector, CSV column, table, column, label).
    let cases = [
        (
            "inv.users",
            Collector::Invictus,
            "DisplayName",
            "users",
            "display_name",
            "Invictus",
        ),
        (
            "hawk.tenant.entra_users",
            Collector::Hawk4,
            "DisplayName",
            "users",
            "display_name",
            "Hawk 4",
        ),
        (
            "hawk.tenant.user_forwarding_report",
            Collector::Hawk3,
            "DisplayName",
            "mailboxes",
            "display_name",
            "Hawk 3",
        ),
    ];
    for (artifact, collector, column, table, db_col, label) in cases {
        let g = builtin("bec-aitm", &GenerateOptions::new(collector, 1));
        let raw = csv_column(&g, artifact, column);
        let case = g.profiled();
        let loaded = db_column(&case, table, db_col);
        for name in &expected {
            assert!(
                raw.contains(name),
                "{label}: {artifact} column {column} lacks {name:?}"
            );
            assert!(
                loaded.contains(name),
                "{label}: {table}.{db_col} lacks {name:?}"
            );
        }
    }

    // Hawk 4 also writes EntraIDUsers through `ConvertTo-Json`; the comma must survive there.
    let g = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let json = json_column(&g, "hawk.tenant.entra_users", "DisplayName");
    for name in &expected {
        assert!(json.contains(name), "Hawk 4 JSON lacks {name:?}");
    }

    // The portal's sign-in export carries the same `User` display names, but only the users
    // with an interactive sign-in in the window; every comma name it does carry must load
    // exactly.
    let g = builtin("bec-aitm", &GenerateOptions::new(Collector::Portal, 1));
    let raw = csv_column(&g, "portal.entra_signins", "User");
    let comma: Vec<String> = raw.into_iter().filter(|n| n.contains(", ")).collect();
    assert!(!comma.is_empty(), "portal: no comma-bearing sign-in name");
    let case = g.profiled();
    let loaded = db_column(&case, "signins", "user_display_name");
    for name in &comma {
        assert!(
            loaded.contains(name),
            "Portal: signins.user_display_name lacks {name:?}"
        );
    }
}

fn no_error_files(report: &sparrow_core::ingest::IngestReport) {
    assert!(
        report
            .collections
            .iter()
            .flat_map(|c| &c.files)
            .all(|f| f.status != FileStatus::Error),
        "{report:#?}"
    );
}

/// Ingest several cached trees into one case and profile once with `geoip`.
fn ingest_many(trees: &[&Generated], geoip: Option<&Path>, as_of: DateTime<Utc>) -> Case {
    let mut case = Case::in_memory().unwrap();
    for g in trees {
        let report = ingest_path(
            &mut case,
            &g.dir,
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
        no_error_files(&report);
    }
    refresh(
        &mut case,
        &ProfileOptions {
            dirs: DataDirs::default(),
            geoip_dir: geoip.map(Path::to_path_buf),
            as_of: Some(as_of),
        },
    )
    .unwrap();
    case
}

/// A Hawk 4 and a portal export of the same world: each table's key set is exactly the union of
/// the two manifests' key sets, in either ingest order, and the portal UAL file's duplicate count
/// is the overlap predicted from those sets.
#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn portal_exports_beside_a_hawk_capture_deduplicate_by_id() {
    let hawk = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let portal = builtin("bec-aitm", &GenerateOptions::new(Collector::Portal, 1));
    let geoip = hawk.dir.join(hawk.manifest.geoip_dir.clone().unwrap());
    let as_of = hawk.manifest.collected_at + Duration::days(1);
    const TABLES: [&str; 3] = ["ual_events", "signins", "message_trace"];

    // The portal's `ual_events` is above the 5000-key listing cap, so its key set is read from a
    // portal-only ingest and checked against the manifest's `keys_sha256` before it is used; the
    // other tables list their keys in the manifests directly.
    let portal_case = ingest_tree(&portal);
    for table in TABLES {
        assert_keys_match_manifest(&portal_case, &portal.manifest, table);
    }
    let manifest_keys = |m: &Manifest, table: &str| -> std::collections::BTreeSet<String> {
        if m.tables[table].keys.is_empty() {
            table_keys(&portal_case, table)
        } else {
            m.tables[table].keys.iter().cloned().collect()
        }
    };
    let mut expected: BTreeMap<&str, std::collections::BTreeSet<String>> = BTreeMap::new();
    for table in TABLES {
        let mut union = manifest_keys(&hawk.manifest, table);
        union.extend(manifest_keys(&portal.manifest, table));
        expected.insert(table, union);
    }

    let mut key_snapshots = Vec::new();
    for (order, portal_second) in [([&hawk, &portal], true), ([&portal, &hawk], false)] {
        let mut case = Case::in_memory().unwrap();
        // The portal may be the first or second collection, so capture its file's counts from
        // whichever ingest actually processed it.
        let mut portal_ual: Option<(u64, u64, u64)> = None;
        for g in order {
            let report = ingest_path(
                &mut case,
                &g.dir,
                &ParserRegistry::builtin(),
                &IngestOptions::default(),
            )
            .unwrap();
            no_error_files(&report);
            if let Some(f) = report
                .collections
                .iter()
                .flat_map(|c| &c.files)
                .find(|f| f.artifact_id.as_deref() == Some("portal.ual"))
            {
                portal_ual = Some((f.records_read, f.records_loaded, f.records_duplicate));
            }
        }
        let (read, loaded, duplicate) = portal_ual.expect("portal.ual file");
        refresh(
            &mut case,
            &ProfileOptions {
                dirs: DataDirs::default(),
                geoip_dir: Some(geoip.clone()),
                as_of: Some(as_of),
            },
        )
        .unwrap();
        let mut snapshot = Vec::new();
        for table in TABLES {
            let keys = table_keys(&case, table);
            assert_eq!(keys, expected[table], "{table} combined keys");
            snapshot.push(keys);
        }
        key_snapshots.push(snapshot);

        // The portal UAL file: when the portal is processed second its rows already seen in the
        // Hawk capture are duplicates (the overlap of the two key sets), the rest are loaded; when
        // it is first it loads everything and the Hawk files are the duplicates.
        let overlap = hawk.manifest.tables["ual_events"].rows
            + portal.manifest.tables["ual_events"].rows
            - expected["ual_events"].len() as u64;
        if portal_second {
            assert_eq!(duplicate, overlap, "portal ual duplicates");
            assert_eq!(
                loaded,
                portal.manifest.tables["ual_events"].rows - overlap,
                "portal ual loaded"
            );
        } else {
            assert_eq!(duplicate, 0, "portal ual first");
            assert_eq!(
                loaded, portal.manifest.tables["ual_events"].rows,
                "portal ual loaded first"
            );
        }
        assert_eq!(
            read, portal.manifest.tables["ual_events"].rows,
            "portal ual rows read"
        );
    }
    assert_eq!(
        key_snapshots[0], key_snapshots[1],
        "the combined key sets depend on the ingest order"
    );

    // The XLSX rendering of the same sign-in export joins the Hawk capture too.
    let mut xlsx_opts = GenerateOptions::new(Collector::Portal, 1);
    xlsx_opts.signin_export = SigninExport::Xlsx;
    let xlsx = builtin("bec-aitm", &xlsx_opts);
    let case = ingest_many(&[&hawk, &xlsx], Some(&geoip), as_of);
    assert!(
        count(&case, "SELECT count(*) FROM signins") == expected["signins"].len() as i64,
        "the XLSX sign-in export did not join the Hawk capture's sign-in key set"
    );
}

/// A full Purview export upgrades the partial rows an earlier capture left behind. The earlier
/// capture is the Microsoft-Extractor-Suite `-AuditDataOnly` window (its MIA rows lose `Folders`),
/// the full copy is the portal's Purview CSV of the same world.
#[test]
fn a_purview_export_upgrades_hawk_partial_rows() {
    let mut hawk_opts = GenerateOptions::new(Collector::Invictus, 1);
    hawk_opts.ual_format = UalFormat::CsvAuditDataOnly;
    let hawk = builtin("bec-aitm", &hawk_opts);
    let portal = builtin("bec-aitm", &GenerateOptions::new(Collector::Portal, 1));
    let geoip = hawk.dir.join(hawk.manifest.geoip_dir.clone().unwrap());
    let as_of = hawk.manifest.collected_at + Duration::days(1);

    // Hawk alone: partial MailItemsAccessed rows exist, their keys are attested by the manifest
    // (the key set hash above 5000), and each has its window's single synthetic child. Record
    // the partial rows and their child counts now, because only a Bind access carries
    // Folders[].FolderItems - a Sync access lists the folder alone, so it legitimately has no
    // per-item message id. The access type of a partial row is unknown until the full copy
    // arrives (the audit-data-only window drops OperationProperties), so which partial row the
    // export turns into a Bind record can only be decided after the upgrade.
    let mut case = ingest_tree(&hawk);
    assert_keys_match_manifest(&case, &hawk.manifest, "ual_events");
    let partial_before: BTreeMap<String, i64> = {
        let mut st = case
            .conn()
            .prepare(
                "SELECT CAST(u.record_id AS VARCHAR),
                        (SELECT count(*) FROM mail_items_accessed x WHERE x.record_id = u.record_id)
                 FROM ual_events u
                 WHERE u.operation = 'MailItemsAccessed' AND u.data_completeness = 'partial'",
            )
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert!(
        !partial_before.is_empty(),
        "the partial capture has no MailItemsAccessed row"
    );
    assert!(
        partial_before.values().all(|n| *n > 0),
        "a partial row has no child: {partial_before:?}"
    );

    // The full export replaces the partial rows and their synthetic children with the real ones.
    let report = ingest_path(
        &mut case,
        &portal.dir,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    no_error_files(&report);
    let portal_ual = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.artifact_id.as_deref() == Some("portal.ual"))
        .expect("portal.ual file");
    assert!(
        portal_ual
            .warnings
            .iter()
            .any(|w| w.contains("replaced partial rows")),
        "the full copy did not report replacing partial rows: {:?}",
        portal_ual.warnings
    );
    refresh(
        &mut case,
        &ProfileOptions {
            dirs: DataDirs::default(),
            geoip_dir: Some(geoip),
            as_of: Some(as_of),
        },
    )
    .unwrap();
    // Pick a row the full copy upgraded to a Bind access with real per-item children - the
    // only kind that has a message id to find. Assert one exists, so the checks below are
    // never vacuous.
    let mut st = case
        .conn()
        .prepare(
            "SELECT CAST(u.record_id AS VARCHAR) FROM ual_events u
             JOIN mail_items_accessed a ON a.record_id = u.record_id
             WHERE u.operation = 'MailItemsAccessed' AND a.access_type = 'bind'
               AND a.internet_message_id IS NOT NULL
             ORDER BY u.record_id",
        )
        .unwrap();
    let upgraded_bind: Vec<String> = st
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .filter(|k| partial_before.contains_key(k))
        .collect();
    assert!(
        !upgraded_bind.is_empty(),
        "the full export upgraded no partial MailItemsAccessed row to a Bind access"
    );
    let key = upgraded_bind[0].clone();
    let children_before = partial_before[&key];
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(data_completeness AS VARCHAR) FROM ual_events WHERE record_id = '{key}'"
            )
        ),
        "full",
        "the partial row was not upgraded"
    );
    let children_after = count(
        &case,
        &format!("SELECT count(*) FROM mail_items_accessed WHERE record_id = '{key}'"),
    );
    let full_children = count(
        &case,
        &format!(
            "SELECT count(*) FROM mail_items_accessed WHERE record_id = '{key}' AND internet_message_id IS NOT NULL"
        ),
    );
    assert!(full_children > 0, "no real child after the upgrade");
    assert!(children_after >= children_before);
}

/// Two captures of one tenant, different `collected_at`: the newer value wins whichever order
/// they are ingested in, and the final state is order-independent.
#[test]
fn two_captures_of_one_tenant_latest_wins_in_either_order() {
    let base = load("bec-aitm").unwrap();
    let mut newer_scenario = base.clone();
    newer_scenario.window.collected_at += Duration::days(2);
    newer_scenario.storylines.push(StorySpec {
        kind: StoryKind::ForwardingMailbox,
        id: "s-extra-fwd".into(),
        actor: Some(3),
        target: None,
        at: At::Day {
            day: 25,
            hour: 10,
            minute: 0,
        },
    });
    let old = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let new = generated(
        "bec-aitm+2d",
        &newer_scenario,
        &GenerateOptions::new(Collector::Hawk4, 1),
    );

    let mut finals = Vec::new();
    for order in [[&old, &new], [&new, &old]] {
        let mut case = Case::in_memory().unwrap();
        for g in order {
            let report = ingest_path(
                &mut case,
                &g.dir,
                &ParserRegistry::builtin(),
                &IngestOptions::default(),
            )
            .unwrap();
            no_error_files(&report);
        }
        let state = snapshot(
            &case,
            "SELECT record_key, forwarding_smtp_address, auto_reply_state FROM mailboxes",
        );
        // The mailbox the newer capture added forwarding for resolves to the newer collection.
        assert!(
            text(
                &case,
                "SELECT c.root_path FROM mailboxes m
                 JOIN collections c ON c.collection_id = CAST(m.column_collections->>'$.forwarding_smtp_address' AS BIGINT)
                 WHERE m.forwarding_smtp_address IS NOT NULL
                 ORDER BY m.record_key LIMIT 1"
            )
            .contains("_20260912_"),
            "the winning forwarding column does not point at the newer capture"
        );
        finals.push(state);
    }
    assert_eq!(
        finals[0], finals[1],
        "the final state depends on the ingest order"
    );
}

/// Detection results of a case as sorted text: findings (id, fingerprint, rule, tenant, actor,
/// severity) and their evidence rows.
fn finding_state(case: &Case) -> (Vec<String>, Vec<String>) {
    let rows = |sql: &str| -> Vec<String> {
        let mut st = case.conn().prepare(sql).unwrap();
        st.query_map([], |r| {
            Ok((0..r.as_ref().column_count())
                .map(|i| format!("{:?}", r.get::<_, duckdb::types::Value>(i).unwrap()))
                .collect::<Vec<_>>()
                .join("|"))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    };
    (
        rows(
            "SELECT finding_id, fingerprint, rule_id, tenant_key, actor_upn, severity FROM findings ORDER BY finding_id",
        ),
        rows(
            "SELECT finding_id, source_table, record_key FROM finding_evidence ORDER BY finding_id, source_table, record_key",
        ),
    )
}

fn detect_now(case: &mut Case, as_of: DateTime<Utc>) {
    sparrow_core::detect::run::run_with_dirs(
        case,
        &DataDirs::default(),
        &sparrow_core::detect::DetectOptions {
            now: Some(as_of),
            ..Default::default()
        },
    )
    .unwrap();
}

/// Ingesting capture A then B, B then A, or A again gives the same findings (fingerprints and
/// evidence sets): detection depends on the evidence, not the ingest order.
#[test]
fn findings_are_order_independent() {
    let base = load("bec-aitm").unwrap();
    let mut newer_scenario = base.clone();
    newer_scenario.window.collected_at += Duration::days(2);
    newer_scenario.storylines.push(StorySpec {
        kind: StoryKind::ForwardingMailbox,
        id: "s-extra-fwd".into(),
        actor: Some(3),
        target: None,
        at: At::Day {
            day: 25,
            hour: 10,
            minute: 0,
        },
    });
    let a = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let b = generated(
        "bec-aitm+2d",
        &newer_scenario,
        &GenerateOptions::new(Collector::Hawk4, 1),
    );
    let geoip = a.dir.join(a.manifest.geoip_dir.clone().unwrap());
    let as_of = b.manifest.collected_at + Duration::days(1);
    let mut states = Vec::new();
    let (ga, gb): (&Generated, &Generated) = (&a, &b);
    for order in [vec![ga, gb], vec![gb, ga], vec![ga, gb, ga]] {
        let mut case = ingest_many(&order, Some(&geoip), as_of);
        detect_now(&mut case, as_of);
        states.push(finding_state(&case));
    }
    assert!(!states[0].0.is_empty(), "the captures produce findings");
    assert!(
        states[0].0.iter().any(|f| f.contains("SPW-HAWK-011")),
        "the extra forwarding storyline is detected"
    );
    assert_eq!(states[0], states[1], "A then B differs from B then A");
    assert_eq!(states[0], states[2], "re-ingesting A changes the findings");
}

/// Ingesting a tree twice adds nothing: every file is a duplicate and table counts are
/// unchanged. Profiling twice leaves the profile snapshots identical.
#[test]
fn reingest_and_reprofile_change_nothing() {
    for c in [Collector::Hawk4, Collector::Invictus] {
        let g = builtin("bec-aitm", &GenerateOptions::new(c, 1));
        let mut case = Case::in_memory().unwrap();
        let first = ingest_path(
            &mut case,
            &g.dir,
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
        no_error_files(&first);
        let profile = ProfileOptions {
            dirs: DataDirs::default(),
            geoip_dir: g.manifest.geoip_dir.as_ref().map(|p| g.dir.join(p)),
            as_of: Some(g.manifest.collected_at + Duration::days(1)),
        };
        refresh(&mut case, &profile).unwrap();
        let relations = [
            "SELECT * FROM tenant",
            "SELECT * FROM tenant_capabilities",
            "SELECT * FROM identities",
            "SELECT * FROM ip_intel",
            "SELECT * EXCLUDE (evaluated_at) FROM evidence_availability",
        ];
        let before: Vec<String> = relations.iter().map(|r| snapshot(&case, r)).collect();
        let tables = [
            "ual_events",
            "signins",
            "mailboxes",
            "record_sources",
            "collector_flags",
        ];
        let counts: Vec<i64> = tables
            .iter()
            .map(|t| count(&case, &format!("SELECT count(*) FROM {t}")))
            .collect();

        let second = ingest_path(
            &mut case,
            &g.dir,
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
        let second_status: BTreeMap<&str, FileStatus> = second
            .collections
            .iter()
            .flat_map(|c| &c.files)
            .map(|f| (f.rel_path.as_str(), f.status))
            .collect();
        for f in first.collections.iter().flat_map(|c| &c.files) {
            if f.status == FileStatus::Parsed {
                assert_eq!(
                    second_status.get(f.rel_path.as_str()),
                    Some(&FileStatus::DuplicateFile),
                    "{}",
                    f.rel_path
                );
            }
        }
        let after: Vec<i64> = tables
            .iter()
            .map(|t| count(&case, &format!("SELECT count(*) FROM {t}")))
            .collect();
        assert_eq!(counts, after, "{c:?}: re-ingest changed table counts");

        refresh(&mut case, &profile).unwrap();
        let again: Vec<String> = relations.iter().map(|r| snapshot(&case, r)).collect();
        for ((r, a), b) in relations.iter().zip(&before).zip(&again) {
            assert_eq!(a, b, "{c:?}: {r} changed on the second profile");
        }
    }
}

fn snapshot(case: &Case, relation: &str) -> String {
    case.conn()
        .query_row(
            &format!(
                "SELECT coalesce(string_agg(CAST(t AS VARCHAR), chr(10) ORDER BY CAST(t AS VARCHAR)), '')
                 FROM ({relation}) t"
            ),
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// GeoIP enrichment marks the attacker's hosting ASNs and leaves the Microsoft Cloud PC ASN
/// alone.
#[test]
fn geoip_enrichment_marks_hosting_and_microsoft_asns() {
    let g = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let case = g.profiled();
    assert!(
        count(&case, "SELECT count(*) FROM ip_intel WHERE is_hosting") > 0,
        "no hosting IP was enriched"
    );
    assert!(
        count(&case, "SELECT count(*) FROM ip_intel WHERE asn = 8075") > 0,
        "no Microsoft ASN was enriched"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ip_intel WHERE asn = 8075 AND is_hosting"
        ),
        0
    );
}

/// Two tenants in one case stay apart: each keeps its own profile (checked against its own
/// manifest's capability and evidence expectations), and their collections stay separate.
#[test]
fn two_tenants_in_one_case_stay_apart() {
    let hawk = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    // The same seed: the tenant id follows the scenario as well as the seed, so two scenarios
    // at one seed are two tenants.
    let inv = builtin(
        "hawk-investigate",
        &GenerateOptions::new(Collector::Invictus, 1),
    );
    let geoip = hawk.dir.join(hawk.manifest.geoip_dir.clone().unwrap());
    let case = ingest_many(
        &[&hawk, &inv],
        Some(&geoip),
        hawk.manifest.collected_at + Duration::days(1),
    );
    let mut case = case;
    // The two scenarios, at the same seed, are two tenants: the id follows the scenario name.
    assert!(
        Uuid::parse_str(&hawk.manifest.tenant.tenant_id).is_ok(),
        "the tenant id is not a GUID: {}",
        hawk.manifest.tenant.tenant_id
    );
    assert_ne!(
        hawk.manifest.tenant.tenant_id, inv.manifest.tenant.tenant_id,
        "two scenarios at one seed share a tenant id"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM tenant"), 2);
    // Detection runs per tenant: no finding cites another tenant's evidence.
    detect_now(&mut case, hawk.manifest.collected_at + Duration::days(1));
    assert_eq!(
        count(
            &case,
            "SELECT count(DISTINCT tenant_key) FROM detection_runs"
        ),
        2
    );
    assert!(count(&case, "SELECT count(*) FROM findings") > 0);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM findings f JOIN finding_evidence e USING (finding_id) \
             JOIN ual_events u ON e.source_table = 'ual_events' AND lower(CAST(u.record_id AS VARCHAR)) = e.record_key \
             JOIN collections c ON c.collection_id = u.collection_id WHERE c.tenant_key <> f.tenant_key"
        ),
        0,
        "a finding cites a UAL record of another tenant"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM findings f JOIN finding_evidence e USING (finding_id) \
             JOIN mailboxes m ON e.source_table = 'mailboxes' AND m.record_key = e.record_key \
             JOIN collections c ON c.collection_id = m.collection_id WHERE c.tenant_key <> f.tenant_key"
        ),
        0,
        "a finding cites a mailbox of another tenant"
    );
    assert_eq!(
        count(&case, "SELECT count(DISTINCT tenant_key) FROM collections"),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collections WHERE tenant_key IS NULL"
        ),
        0
    );
    // `check` compares tables case-wide, so a two-tenant case is checked here per tenant from
    // the manifest's own capability and evidence expectations.
    for m in [&hawk.manifest, &inv.manifest] {
        let key = m.tenant.tenant_id.to_string().to_lowercase();
        assert_eq!(
            count(
                &case,
                &format!("SELECT count(*) FROM evidence_availability WHERE tenant_key = '{key}'")
            ),
            EVIDENCE.len() as i64,
            "{key}: evidence rows"
        );
        for (id, want) in &m.evidence {
            let status: String = case
                .conn()
                .query_row(
                    "SELECT CAST(status AS VARCHAR) FROM evidence_availability WHERE tenant_key = ? AND evidence = ?",
                    duckdb::params![key, id],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                want.allowed.contains(&status),
                "{key}/{id}: {status} not one of {:?}",
                want.allowed
            );
        }
        for (cap, want) in &m.capabilities {
            let (status, confidence): (String, Option<String>) = case
                .conn()
                .query_row(
                    "SELECT CAST(status AS VARCHAR), CAST(confidence AS VARCHAR)
                     FROM tenant_capabilities WHERE tenant_key = ? AND capability_id = ?",
                    duckdb::params![key, cap],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(status, want.status, "{key}/{cap}");
            assert_eq!(confidence, want.confidence, "{key}/{cap}");
        }
    }
}

/// Discovery is by content, not folder name: a Hawk 3 tree whose root is renamed is still found
/// and loaded (the tree is generated fresh, not shared).
#[test]
fn hawk3_root_renamed_is_still_found_by_content() {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(
        &load("bec-aitm").unwrap(),
        &GenerateOptions::new(Collector::Hawk3, 1),
        dir.path(),
    )
    .unwrap();
    let renamed = dir.path().join("capture-a");
    std::fs::rename(dir.path().join(&m.root), &renamed).unwrap();
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        &renamed,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert_eq!(report.collections.len(), 1);
    assert_eq!(report.collections[0].tool, Tool::Hawk);
    no_error_files(&report);
}

/// One run ingests collections oldest first and reports them in the given order.
#[test]
fn one_run_ingests_collections_oldest_first_and_reports_in_the_given_order() {
    let mut newer = load("bec-aitm").unwrap();
    newer.window.collected_at += Duration::days(2);
    let newer = generated(
        "bec-aitm+2d-plain",
        &newer,
        &GenerateOptions::new(Collector::Hawk4, 1),
    );
    let older = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let mut given = discover_collections(&newer.dir).unwrap();
    given.extend(discover_collections(&older.dir).unwrap());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_collections(
        &mut case,
        &given,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    no_error_files(&report);
    let roots: Vec<_> = report.collections.iter().map(|c| c.root.clone()).collect();
    assert!(
        roots[0].contains("Hawk_Contoso_Example_20260912"),
        "{roots:?}"
    );
    assert!(
        roots[1].contains("Hawk_Contoso_Example_20260910"),
        "{roots:?}"
    );
    assert!(
        text(
            &case,
            "SELECT root_path FROM collections ORDER BY collection_id LIMIT 1"
        )
        .contains("_20260910_"),
        "the older capture is processed (and registered) first"
    );
}

/// Columns only an older capture supplies survive in either ingest order, and their
/// `column_collections` still names the older collection. The newer capture is the same world
/// two days later with the `autoreply_enabled` storyline removed, so its tree has no
/// `AutoReply_<u>.txt` and the auto-reply columns can only come from the older one.
#[test]
fn older_only_columns_survive_in_either_order() {
    let base = load("bec-aitm").unwrap();
    let mut newer_scenario = base.clone();
    newer_scenario.window.collected_at += Duration::days(2);
    newer_scenario
        .storylines
        .retain(|s| s.kind != StoryKind::AutoreplyEnabled);
    let old = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let new = generated(
        "bec-aitm-noauto",
        &newer_scenario,
        &GenerateOptions::new(Collector::Hawk4, 1),
    );
    assert!(
        !new.manifest
            .files
            .iter()
            .any(|f| f.rel_path.contains("AutoReply_")),
        "the newer tree still has an AutoReply file"
    );
    assert!(
        old.manifest
            .files
            .iter()
            .any(|f| f.rel_path.contains("AutoReply_")),
        "the older tree has no AutoReply file"
    );

    let mut finals = Vec::new();
    for order in [[&old, &new], [&new, &old]] {
        let mut case = Case::in_memory().unwrap();
        for g in order {
            ingest_into(&mut case, g);
        }
        assert!(
            count(
                &case,
                "SELECT count(*) FROM mailboxes WHERE auto_reply_state IS NOT NULL"
            ) > 0,
            "auto_reply_state did not survive"
        );
        assert!(
            count(
                &case,
                "SELECT count(*) FROM mailboxes WHERE auto_reply_external_audience IS NOT NULL"
            ) > 0,
            "auto_reply_external_audience did not survive"
        );
        for column in ["auto_reply_state", "auto_reply_external_audience"] {
            assert!(
                text(
                    &case,
                    &format!(
                        "SELECT c.root_path FROM mailboxes m
                         JOIN collections c ON c.collection_id = CAST(m.column_collections->>'$.{column}' AS BIGINT)
                         WHERE m.{column} IS NOT NULL ORDER BY m.record_key LIMIT 1"
                    )
                )
                .contains("_20260910_"),
                "{column} does not point at the older capture"
            );
        }
        finals.push(snapshot(
            &case,
            "SELECT record_key, auto_reply_state, auto_reply_external_audience FROM mailboxes",
        ));
    }
    assert_eq!(
        finals[0], finals[1],
        "the older-only columns depend on the ingest order"
    );
}

/// The profile's `timeline` has one row per event record of every event table the manifest
/// lists, every row carries `source_refs`, and one storyline user's UPN, object id and PUID
/// converge on one identity.
#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn profile_timeline_and_identities_cover_the_window() {
    const EVENT_TABLES: [&str; 9] = [
        "ual_events",
        "signins",
        "directory_audits",
        "message_trace",
        "mailbox_audit_legacy",
        "admin_audit_events",
        "risk_detections",
        "azure_activity",
        "security_alerts",
    ];
    for c in [Collector::Invictus, Collector::Hawk4] {
        let g = builtin("bec-aitm", &GenerateOptions::new(c, 1));
        let case = g.profiled();
        let mut stmt = case
            .conn()
            .prepare("SELECT source_table, count(*) FROM timeline GROUP BY source_table")
            .unwrap();
        let actual: BTreeMap<String, i64> = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for table in EVENT_TABLES {
            match g.manifest.tables.get(table) {
                Some(expect) if expect.rows > 0 => assert_eq!(
                    actual.get(table).copied().unwrap_or(0) as u64,
                    expect.rows,
                    "{c:?}: timeline {table}"
                ),
                _ => assert_eq!(
                    actual.get(table).copied().unwrap_or(0),
                    0,
                    "{c:?}: timeline {table}"
                ),
            }
        }
        assert_eq!(
            count(
                &case,
                "SELECT count(*) FROM timeline WHERE source_refs IS NULL OR len(source_refs) = 0"
            ),
            0,
            "{c:?}: a timeline row has no source_refs"
        );

        // One storyline user: the manifest names the actor; its UPN, object id and PUID must
        // resolve to one identity through `identity_aliases`.
        let upn = g
            .manifest
            .storylines
            .iter()
            .find(|s| s.polarity == "positive" && !s.actor.is_empty())
            .expect("a positive storyline with an actor")
            .actor
            .to_lowercase();
        let identity: String = case
            .conn()
            .query_row(
                "SELECT identity_id FROM identity_aliases WHERE alias_type = 'upn' AND alias = ?",
                duckdb::params![upn],
                |r| r.get(0),
            )
            .unwrap_or_else(|e| panic!("{c:?} {upn}: {e}"));
        let (object_id, puid): (Option<String>, Option<String>) = case
            .conn()
            .query_row(
                "SELECT object_id, puid FROM identities WHERE identity_id = ?",
                duckdb::params![identity],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let object_id = object_id.unwrap_or_else(|| panic!("{c:?} {upn}: no object id"));
        let puid = puid.unwrap_or_else(|| panic!("{c:?} {upn}: no puid"));
        let id_of = |alias_type: &str, alias: &str| -> String {
            case.conn()
                .query_row(
                    "SELECT identity_id FROM identity_aliases WHERE alias_type = ? AND alias = ?",
                    duckdb::params![alias_type, alias],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(
            id_of("object_id", &object_id),
            identity,
            "{c:?} {upn} object id"
        );
        assert_eq!(id_of("puid", &puid), identity, "{c:?} {upn} puid");
    }
}

/// The Hawk 4 state capture's audit configuration matches the scenario's audit profile:
/// bec-aitm's `search_audited` reports UnifiedAuditLogIngestionEnabled true and AuditDisabled
/// false (the old `state_e2e` asserted `false|false` on its own `default` fixture).
#[test]
fn hawk4_audit_config_matches_the_audit_profile() {
    let g = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let case = g.profiled();
    assert_eq!(
        text(
            &case,
            "SELECT CAST(unified_audit_log_ingestion_enabled AS VARCHAR) || '|' || CAST(audit_disabled AS VARCHAR)
             FROM audit_config"
        ),
        "true|false"
    );
    assert_eq!(
        text(
            &case,
            "SELECT CAST(unified_audit_log_ingestion_enabled AS VARCHAR) FROM audit_config"
        ),
        "true"
    );
}
