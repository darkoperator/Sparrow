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
use sparrow_synth::check::check;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::manifest::Manifest;
use sparrow_synth::options::{Collector, Culture, GenerateOptions, PsEdition, SigninExport};
use sparrow_synth::scenario::{At, Scenario, StoryKind, StorySpec, builtin_names, load};
use sparrow_synth::testing::ingest_generated;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// One generated tree: the parent dir that holds `<manifest.root>` and the manifest.
struct Generated {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    manifest: Manifest,
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
    let dir = tempfile::tempdir().unwrap();
    let manifest = generate_to_dir(scenario, opts, dir.path()).unwrap();
    let dir_path = dir.path().to_path_buf();
    let g = Arc::new(Generated {
        _dir: dir,
        dir: dir_path,
        manifest,
    });
    CACHE.lock().unwrap().insert(key, g.clone());
    g
}

/// The built-in scenario `name` generated with `opts`, cached.
fn builtin(name: &str, opts: &GenerateOptions) -> Arc<Generated> {
    generated(name, &load(name).unwrap(), opts)
}

/// Generate `name` for `opts`, ingest and profile it, and `check` it against its manifest.
fn checked(name: &str, opts: &GenerateOptions) {
    let g = builtin(name, opts);
    let r = check(&g.manifest, &ingest_generated(&g.dir, &g.manifest)).unwrap();
    assert!(
        r.ok,
        "{name} {:?} seed {}: {:#?}",
        opts.collector, opts.seed, r.problems
    );
}

#[test]
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
#[test]
fn storyline_records_verify_against_the_original_files() {
    for c in Collector::ALL {
        let g = builtin("bec-aitm", &GenerateOptions::new(*c, 1));
        let case = ingest_generated(&g.dir, &g.manifest);
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
        let case = ingest_generated(&g.dir, &g.manifest);
        assert!(
            count(&case, "SELECT count(*) FROM collector_flags") > 0,
            "{c:?}: no flags"
        );
        assert_flags_resolve(&case);
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

/// A Hawk 4 and a portal export of the same world: the UAL and sign-in keys deduplicate by id,
/// and a key carries sightings from both collections.
#[test]
fn portal_exports_beside_a_hawk_capture_deduplicate_by_id() {
    let hawk = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let portal = builtin("bec-aitm", &GenerateOptions::new(Collector::Portal, 1));
    let geoip = hawk.dir.join(hawk.manifest.geoip_dir.clone().unwrap());
    let case = ingest_many(
        &[&hawk, &portal],
        Some(&geoip),
        hawk.manifest.collected_at + Duration::days(1),
    );

    assert_eq!(count(&case, "SELECT count(*) FROM collections"), 2);
    for key in ["ual_events", "signins"] {
        let rows = hawk.manifest.tables[key].rows + portal.manifest.tables[key].rows;
        let union = count(&case, &format!("SELECT count(*) FROM {key}"));
        assert!(
            union < rows as i64,
            "{key}: the two captures did not deduplicate ({union} vs {rows})"
        );
        assert!(
            count(
                &case,
                &format!(
                    "SELECT count(*) FROM (
                       SELECT rs.record_key,
                         max(CASE WHEN sf.collection_id IN (SELECT collection_id FROM collections WHERE root_path LIKE '%Hawk%') THEN 1 ELSE 0 END) AS in_hawk,
                         max(CASE WHEN sf.collection_id IN (SELECT collection_id FROM collections WHERE root_path LIKE '%Portal%') THEN 1 ELSE 0 END) AS in_portal
                       FROM record_sources rs JOIN source_files sf USING (file_id)
                       WHERE rs.table_name = '{key}'
                       GROUP BY rs.record_key
                     ) x WHERE in_hawk > 0 AND in_portal > 0"
                )
            ) > 0,
            "{key}: no key is seen through both collectors"
        );
    }

    // The XLSX rendering of the same sign-in export joins the Hawk capture too.
    let mut xlsx_opts = GenerateOptions::new(Collector::Portal, 1);
    xlsx_opts.signin_export = SigninExport::Xlsx;
    let xlsx = builtin("bec-aitm", &xlsx_opts);
    let case = ingest_many(
        &[&hawk, &xlsx],
        Some(&geoip),
        hawk.manifest.collected_at + Duration::days(1),
    );
    assert!(
        count(&case, "SELECT count(*) FROM signins")
            < (hawk.manifest.tables["signins"].rows + xlsx.manifest.tables["signins"].rows) as i64,
        "the XLSX sign-in export did not deduplicate"
    );
}

/// A full Purview export upgrades the partial rows a Hawk 4 capture left behind.
#[test]
fn a_purview_export_upgrades_hawk_partial_rows() {
    let hawk = builtin("bec-aitm", &GenerateOptions::new(Collector::Hawk4, 1));
    let portal = builtin("bec-aitm", &GenerateOptions::new(Collector::Portal, 1));
    let geoip = hawk.dir.join(hawk.manifest.geoip_dir.clone().unwrap());
    let case = ingest_many(
        &[&hawk, &portal],
        Some(&geoip),
        hawk.manifest.collected_at + Duration::days(1),
    );
    // The portal's full UAL export replaces the Hawk partial rows with full ones.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'partial'"
        ),
        0,
        "a partial row survived the full export"
    );
    assert!(count(&case, "SELECT count(*) FROM ual_events") > 0);
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
    let case = ingest_generated(&g.dir, &g.manifest);
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
    // A different seed: the tenant id derives from the seed, so the two scenarios would
    // otherwise share one tenant.
    let inv = builtin(
        "hawk-investigate",
        &GenerateOptions::new(Collector::Invictus, 2),
    );
    let geoip = hawk.dir.join(hawk.manifest.geoip_dir.clone().unwrap());
    let case = ingest_many(
        &[&hawk, &inv],
        Some(&geoip),
        hawk.manifest.collected_at + Duration::days(1),
    );
    assert_ne!(
        hawk.manifest.tenant.tenant_id,
        inv.manifest.tenant.tenant_id
    );
    assert_eq!(count(&case, "SELECT count(*) FROM tenant"), 2);
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
