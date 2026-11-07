use sparrow_synth::cache::{Cache, CachedCase, Stage};
use sparrow_synth::check::check_without_detection as check;
use sparrow_synth::generate::{generate, generate_with_policy};
use sparrow_synth::options::{Collector, Culture, GenerateOptions, PsEdition, UalFormat};
use sparrow_synth::reserved::scan_text;
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::tree::{CulturePolicy, MemSink};

static CACHE: std::sync::LazyLock<Cache> =
    std::sync::LazyLock::new(|| sparrow_synth::test_cache!());

/// The tree and a private profiled case of `s`/`o`, from the cross-binary test cache.
fn cached(s: &sparrow_synth::scenario::Scenario, o: &GenerateOptions) -> CachedCase {
    CACHE
        .case(s, o, Stage::Profiled)
        .unwrap_or_else(|e| panic!("cached case: {e}"))
}

fn opts(seed: u64) -> GenerateOptions {
    GenerateOptions::new(Collector::Invictus, seed)
}

fn green(name: &str, o: &GenerateOptions) -> sparrow_synth::manifest::Manifest {
    let got = cached(&load(name).unwrap(), o);
    let report = check(&got.tree.manifest, &got.case).unwrap();
    assert!(report.ok, "{name} {o:?}: {:#?}", report.problems);
    got.tree.manifest.clone()
}

/// Fast representative of the every-scenario matrix below: bec-aitm on both PowerShell editions.
#[test]
fn bec_aitm_checks_green_on_ps7_and_ps51() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let mut o = opts(21);
        o.ps = ps;
        green("bec-aitm", &o);
    }
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn every_builtin_checks_green_on_ps7_and_ps51() {
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for ps in [PsEdition::Ps7, PsEdition::Ps51] {
            let mut o = opts(21);
            o.ps = ps;
            green(name, &o);
        }
    }
}

fn ual_format_checks_green(f: UalFormat) {
    let mut o = opts(22);
    o.ual_format = f;
    let m = green("bec-aitm", &o);
    assert!(
        m.files
            .iter()
            .any(|x| x.artifact_id.as_deref() == Some("inv.ual.window") && x.status == "parsed"),
        "{f:?}"
    );
    assert!(
        m.files
            .iter()
            .any(|x| x.artifact_id.as_deref() == Some("inv.ual.merged")
                && x.status == "skipped_superseded"),
        "{f:?}"
    );
}

/// Fast representative of the every-format matrix below: the first Get-UAL format.
#[test]
fn first_get_ual_format_checks_green() {
    ual_format_checks_green(UalFormat::ALL[0]);
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn every_get_ual_format_checks_green() {
    for f in UalFormat::ALL {
        ual_format_checks_green(*f);
    }
}

#[test]
fn day_first_culture_trees_ingest_without_culture_flag() {
    for c in [Culture::EnGb, Culture::DeDe, Culture::JaJp] {
        let mut o = opts(23);
        o.culture = c;
        let m = green("bec-e3-audit-gaps", &o);
        assert_eq!(
            m.ingest_culture, None,
            "{c:?}: a 30-day window proves the order"
        );
    }
}

#[test]
fn all_ambiguous_collection_needs_culture() {
    // A one-week window before the 13th, with `pin_ambiguous_dates` moving every historical
    // state date to day 1: no culture date in the collection can prove the order, whatever
    // dated files the writers add later.
    let mut s = load("business-basic").unwrap();
    s.window.start = "2026-09-01T00:00:00Z".parse().unwrap();
    s.window.days = 7;
    s.window.collected_at = "2026-09-09T10:00:00Z".parse().unwrap();
    s.pin_ambiguous_dates = true;
    s.storylines.clear();
    s.lookalikes.clear();
    let mut o = opts(24);
    o.culture = Culture::EnGb;
    let mut sink = MemSink::default();
    let failing = generate_with_policy(&s, &o, &mut sink, CulturePolicy::Never).unwrap();
    assert!(failing.files.iter().any(|f| f.status == "error"));
    // Ingesting with the culture (what `ingest_generated` passes) loads every file and `check`
    // is green: the collection really is only unusable without `--culture`.
    let got = cached(&s, &o);
    let m = got.tree.manifest.clone();
    assert_eq!(m.ingest_culture.as_deref(), Some("en-GB"));
    let case = got.case;
    let errors: i64 = case
        .conn()
        .query_row(
            "SELECT count(*) FROM source_files WHERE status = 'error'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(errors, 0, "a file stayed in error with the culture");
    let report = check(&m, &case).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
}

#[test]
fn empty_exports_read_as_ran_and_found_nothing() {
    let m = green("business-basic", &opts(25)); // no Entra ID P1: Graph sign-ins refused
    assert!(
        m.empty_dirs
            .iter()
            .any(|d| d.ends_with("/interactiveUser & nonInteractiveUser"))
    );
    assert!(m.empty_dirs.iter().any(|d| d.ends_with("/managedIdentity")));
    assert_eq!(m.evidence["signins"].allowed, vec!["collected".to_string()]);
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.contains("MessageTrace") && f.status == "duplicate_file")
    );
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn same_second_sign_in_pages_share_a_file() {
    let mut sink = MemSink::default();
    let mut s = load("volume").unwrap();
    s.tenant.users = 40; // enough sign-ins for 3+ pages, still quick
    // Look-alikes of users 50 and 60 do not exist in a 40-user tenant.
    s.lookalikes
        .retain(|l| l.actor.unwrap_or(1) <= 40 && l.target.unwrap_or(1) <= 40);
    let m = generate(&s, &opts(26), &mut sink).unwrap();
    let pages: Vec<_> = sink
        .files
        .iter()
        .filter(|(k, _)| k.ends_with("-SignInLogs.json") && !k.contains("/Merged/"))
        .collect();
    assert!(
        pages
            .iter()
            .any(|(_, v)| String::from_utf8_lossy(v).contains("]\r\n[")),
        "no concatenated page"
    );
    assert!(
        m.files
            .iter()
            .filter(|f| f.artifact_id.as_deref() == Some("inv.signins"))
            .all(|f| f.status == "parsed")
    );
}

#[test]
fn trees_are_deterministic_and_clean() {
    let s = load("bec-aitm").unwrap();
    let (mut a, mut b) = (MemSink::default(), MemSink::default());
    generate(&s, &opts(27), &mut a).unwrap();
    generate(&s, &opts(27), &mut b).unwrap();
    assert_eq!(a.files, b.files);
    for (rel, bytes) in &a.files {
        if rel.ends_with(".mmdb") {
            continue;
        }
        let found = scan_text(&sparrow_core::readers::text::decode(bytes).text);
        assert!(found.is_empty(), "{rel}: {found:?}");
    }
}

// Unix only: a file name cannot hold a backslash on Windows.
#[cfg(unix)]
#[test]
fn non_windows_log_sits_beside_output_and_the_project_is_the_collection() {
    let mut o = opts(28);
    o.non_windows = true;
    let got = cached(&load("business-basic").unwrap(), &o);
    let (m, dir) = (got.tree.manifest.clone(), got.tree.dir.clone());
    assert_eq!(m.root, "Output/Adatum_Example");
    let log = std::fs::read(dir.join("Output\\LogFile.txt")).unwrap();
    assert!(log.starts_with(b"20") && !log.windows(2).any(|w| w == b"\r\n"));
    assert!(!m.files.iter().any(|f| f.rel_path.ends_with("LogFile.txt")));
    let trace = m
        .files
        .iter()
        .find(|f| f.artifact_id.as_deref() == Some("inv.message_trace"))
        .unwrap();
    let bytes = std::fs::read(dir.join(&m.root).join(&trace.rel_path)).unwrap();
    assert!(!bytes.windows(2).any(|w| w == b"\r\n"), "LF line ends");
    let report = check(&m, &got.case).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
}

// Unix only: a file name cannot hold a backslash on Windows.
#[cfg(unix)]
#[test]
fn non_windows_triage_folder_keeps_the_literal_backslash_name() {
    let mut o = opts(29);
    o.non_windows = true;
    let got = cached(&load("bec-aitm").unwrap(), &o);
    let (m, dir) = (got.tree.manifest.clone(), got.tree.dir.clone());
    assert_eq!(m.root, "Output/Contoso_Example");
    // The collector's `Output\<TriageName>` has no separator on non-Windows, so it is one
    // directory literally named `Output\Triage-Contoso_Example` beside `Output/`, outside the
    // collection; the file is unlisted.
    assert!(
        !m.files
            .iter()
            .any(|f| f.artifact_id.as_deref() == Some("inv.user_applications")),
        "the unlisted triage file must not be in the manifest"
    );
    let triage = dir.join("Output\\Triage-Contoso_Example");
    assert!(triage.is_dir(), "no literal-backslash triage folder");
    let names: Vec<String> = std::fs::read_dir(&triage)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with("-UserApplications.csv")),
        "{names:?}"
    );
    let report = check(&m, &got.case).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
}

/// With `invictus_manifests` the Invictus logs carry complete collection manifests: quiet
/// sources read "collected, no events" and nothing is a collector gap or an incomplete banner.
#[test]
fn invictus_manifests_make_quiet_sources_collected() {
    use sparrow_core::case::collector::incomplete_collection;
    use sparrow_core::case::coverage::{CoverageOptions, coverage};

    let mut o = opts(31);
    o.invictus_manifests = true;
    let got = cached(&load("bec-aitm").unwrap(), &o);
    let report = check(&got.tree.manifest, &got.case).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
    // Accounts need the detection roll-up.
    let got = CACHE
        .case(&load("bec-aitm").unwrap(), &o, Stage::Detected)
        .unwrap();
    assert!(
        got.tree
            .manifest
            .files
            .iter()
            .any(
                |f| f.artifact_id.as_deref() == Some("inv.collection_manifest")
                    && f.status == "parsed"
            )
    );
    // Like the real writer, `files` lists the data files (relative to the manifest's folder, nested
    // ones included) and never the merged output.
    let mut listed = Vec::new();
    for f in &got.tree.manifest.files {
        if f.artifact_id.as_deref() == Some("inv.collection_manifest") {
            let path = got.tree.dir.join(&got.tree.manifest.root).join(&f.rel_path);
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            for u in v["units"].as_array().unwrap() {
                for name in u["files"].as_array().unwrap() {
                    listed.push(name.as_str().unwrap().to_string());
                }
            }
        }
    }
    assert!(listed.iter().all(|n| !n.contains("Merged")), "{listed:?}");
    assert!(
        listed
            .iter()
            .any(|n| n.starts_with("interactiveUser-nonInteractiveUser/")
                || n.starts_with("interactiveUser & nonInteractiveUser/")),
        "{listed:?}"
    );
    assert!(listed.iter().any(|n| n.starts_with("UAL-")), "{listed:?}");
    let conn = got.case.conn();
    let cov = coverage(conn, &CoverageOptions::default()).unwrap();
    assert!(cov.collector_requests.is_empty());
    let scenario = load("bec-aitm").unwrap();
    let (from, to) = (
        scenario.window.start.date_naive(),
        scenario.window_end().date_naive(),
    );
    // An account the tenant never audited: no rows, but the collector vouches the window.
    let opts_q = CoverageOptions {
        users: vec!["quiet.user@contoso.example".to_string()],
        ..CoverageOptions::default()
    };
    let q = coverage(conn, &opts_q).unwrap();
    let ual = q.accounts[0]
        .sources
        .iter()
        .find(|s| s.source == "ual")
        .unwrap();
    assert_eq!(ual.rows, 0);
    assert!(ual.collected_no_events, "{ual:?}");
    for a in &cov.accounts {
        for s in &a.sources {
            for g in &s.gaps {
                assert_ne!(g.reason, "collector_gap", "{} {}", a.upn, s.source);
            }
            if s.source == "ual" {
                // The manifests vouch the window [start, end): no such gap may lie inside it.
                assert!(
                    s.gaps.iter().all(|g| !matches!(
                        g.reason.as_str(),
                        "absent" | "before" | "after"
                    ) || g.to < from
                        || g.from >= to),
                    "{}: {:?}",
                    a.upn,
                    s.gaps
                );
                if s.rows == 0 {
                    assert!(s.collected_no_events, "{}", a.upn);
                }
            }
        }
    }
    assert!(incomplete_collection(conn).unwrap().is_none());
}
