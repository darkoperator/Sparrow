use sparrow_synth::cache::{Cache, CachedCase, Stage};
use sparrow_synth::check::check_without_detection as check;
use sparrow_synth::generate::{generate, generate_to_dir};
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::reserved::scan_text;
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::tree::MemSink;

static CACHE: std::sync::LazyLock<Cache> =
    std::sync::LazyLock::new(|| sparrow_synth::test_cache!());

/// The tree and a private profiled case of `s`/`o`, from the cross-binary test cache.
fn cached(s: &sparrow_synth::scenario::Scenario, o: &GenerateOptions) -> CachedCase {
    CACHE
        .case(s, o, Stage::Profiled)
        .unwrap_or_else(|e| panic!("cached case: {e}"))
}

fn opts(seed: u64) -> GenerateOptions {
    GenerateOptions::new(Collector::Hawk4, seed)
}

fn green(name: &str, o: &GenerateOptions) -> sparrow_synth::manifest::Manifest {
    let got = cached(&load(name).unwrap(), o);
    let report = check(&got.tree.manifest, &got.case).unwrap();
    assert!(report.ok, "{name} {o:?}: {:#?}", report.problems);
    got.tree.manifest.clone()
}

/// Every built-in scenario but `volume`.
const MATRIX: &[&str] = &[
    "audit-tamper",
    "bec-aitm",
    "bec-e3-audit-gaps",
    "bec-o365-no-p1",
    "business-basic",
    "hawk-investigate",
    "password-spray",
];

#[test]
fn the_matrix_covers_every_builtin_but_volume() {
    let builtins: Vec<&str> = builtin_names()
        .iter()
        .copied()
        .filter(|n| *n != "volume")
        .collect();
    assert_eq!(builtins, MATRIX);
}

/// One test per scenario × edition, so the harness runs them in parallel.
macro_rules! green_matrix {
    ($($test:ident: $scenario:literal, $ps:expr, $mixed:literal;)+) => {
        $(
            #[test]
            fn $test() {
                let mut o = opts(31);
                o.ps = $ps;
                o.hawk_mixed_editions = $mixed;
                green($scenario, &o);
            }
        )+
    };
}

green_matrix! {
    audit_tamper_ps7: "audit-tamper", PsEdition::Ps7, false;
    audit_tamper_ps51: "audit-tamper", PsEdition::Ps51, false;
    audit_tamper_mixed: "audit-tamper", PsEdition::Ps7, true;
    bec_aitm_ps7: "bec-aitm", PsEdition::Ps7, false;
    bec_aitm_ps51: "bec-aitm", PsEdition::Ps51, false;
    bec_aitm_mixed: "bec-aitm", PsEdition::Ps7, true;
    bec_e3_audit_gaps_ps7: "bec-e3-audit-gaps", PsEdition::Ps7, false;
    bec_e3_audit_gaps_ps51: "bec-e3-audit-gaps", PsEdition::Ps51, false;
    bec_e3_audit_gaps_mixed: "bec-e3-audit-gaps", PsEdition::Ps7, true;
    bec_o365_no_p1_ps7: "bec-o365-no-p1", PsEdition::Ps7, false;
    bec_o365_no_p1_ps51: "bec-o365-no-p1", PsEdition::Ps51, false;
    bec_o365_no_p1_mixed: "bec-o365-no-p1", PsEdition::Ps7, true;
    business_basic_ps7: "business-basic", PsEdition::Ps7, false;
    business_basic_ps51: "business-basic", PsEdition::Ps51, false;
    business_basic_mixed: "business-basic", PsEdition::Ps7, true;
    hawk_investigate_ps7: "hawk-investigate", PsEdition::Ps7, false;
    hawk_investigate_ps51: "hawk-investigate", PsEdition::Ps51, false;
    hawk_investigate_mixed: "hawk-investigate", PsEdition::Ps7, true;
    password_spray_ps7: "password-spray", PsEdition::Ps7, false;
    password_spray_ps51: "password-spray", PsEdition::Ps51, false;
    password_spray_mixed: "password-spray", PsEdition::Ps7, true;
}

#[test]
fn file_names_use_the_short_user_suffix() {
    let mut sink = MemSink::default();
    let m = generate(&load("hawk-investigate").unwrap(), &opts(32), &mut sink).unwrap();
    let names: Vec<&str> = m.files.iter().map(|f| f.rel_path.as_str()).collect();
    let upn_dir = names
        .iter()
        .find(|n| n.contains("@") && n.contains("/InboxRules_") && n.ends_with(".json"))
        .unwrap();
    let (dir, file) = upn_dir.split_once('/').unwrap();
    let short = dir.split('@').next().unwrap();
    assert_eq!(file, format!("InboxRules_{short}.json").as_str());
}

#[test]
fn hawk_bug_flags_the_benign_admin_rule_but_the_manifest_says_no_hit() {
    let mut sink = MemSink::default();
    let m = generate(&load("hawk-investigate").unwrap(), &opts(33), &mut sink).unwrap();
    assert!(m.files.iter().any(|f| {
        f.rel_path
            .ends_with("_Investigate_Admin_Inbox_Rules_Creation.json")
    }));
    let r = m
        .rules
        .iter()
        .find(|r| r.rule_id == "SPW-HAWK-001" && r.storyline == "l-admok")
        .unwrap();
    assert_eq!(format!("{:?}", r.outcome), "NoHit");
}

#[test]
fn simple_files_are_superseded_and_json_beats_csv() {
    let m = green("hawk-investigate", &opts(34));
    for f in &m.files {
        let name = f.rel_path.rsplit('/').next().unwrap();
        if name.starts_with("Simple_")
            || name.contains("_Simple_")
            || name.starts_with("Converted_")
        {
            assert_eq!(f.status, "skipped_superseded", "{}", f.rel_path);
        }
        if name.ends_with(".csv")
            && m.files
                .iter()
                .any(|j| j.rel_path == f.rel_path.replace(".csv", ".json") && j.status == "parsed")
        {
            assert!(
                f.status == "skipped_superseded" || f.status == "duplicate_file",
                "{}",
                f.rel_path
            );
        }
    }
}

#[test]
fn non_windows_writes_the_literal_backslash_tenant_folder() {
    let mut o = opts(35);
    o.non_windows = true;
    let m = green("bec-aitm", &o);
    assert!(m.files.iter().any(|f| f.rel_path.starts_with("\\Tenant/")));
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.starts_with("Tenant/EDiscoveryRoles"))
    );
}

#[test]
fn trees_are_deterministic_and_clean() {
    let s = load("hawk-investigate").unwrap();
    let (mut a, mut b) = (MemSink::default(), MemSink::default());
    generate(&s, &opts(36), &mut a).unwrap();
    generate(&s, &opts(36), &mut b).unwrap();
    assert_eq!(a.files, b.files);
    for (rel, bytes) in &a.files {
        if rel.ends_with(".mmdb") {
            continue;
        }
        let found = scan_text(&sparrow_core::readers::text::decode(bytes).text);
        assert!(found.is_empty(), "{rel}: {found:?}");
    }
}

/// In a Hawk 4 `Entra_Sign_In_Log_*.csv` the Status cell holds a .NET type name, so a sign-in read
/// from the CSV has no result. Every Hawk 4 user folder carries the JSON twin, which supersedes the
/// CSV (its rows hold the Status object); when only the CSV exists, the parser must not pretend and
/// the evidence availability says the sign-in result was not collected.
#[test]
fn a_csv_only_hawk4_sign_in_folder_says_the_result_was_not_collected() {
    use sparrow_synth::testing::ingest_generated;
    let scenario = load("bec-aitm").unwrap();
    let signin_note = |case: &sparrow_core::Case| -> String {
        case.conn()
            .query_row(
                "SELECT reason FROM evidence_availability WHERE evidence = 'signins'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    let counts = |case: &sparrow_core::Case| -> (i64, i64) {
        case.conn()
            .query_row(
                "SELECT count(*), count(*) FILTER (WHERE error_code IS NULL) FROM signins",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    };
    let json_twins =
        |dir: &std::path::Path| -> Vec<std::path::PathBuf> {
            let mut out = Vec::new();
            let mut stack = vec![dir.to_path_buf()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).unwrap() {
                    let p = e.unwrap().path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                        n.starts_with("Entra_Sign_In_Log_") && n.ends_with(".json")
                    }) {
                        out.push(p);
                    }
                }
            }
            out
        };

    // With the JSON twins: the result is known and the availability note is absent.
    let got = cached(&scenario, &opts(5));
    assert!(
        !json_twins(&got.tree.dir).is_empty(),
        "the tree has JSON twins"
    );
    let case = got.case;
    let (total, unknown) = counts(&case);
    assert!(total > 0);
    assert_eq!(unknown, 0, "the JSON twin supersedes the CSV");
    assert!(
        !signin_note(&case).contains("no result"),
        "{}",
        signin_note(&case)
    );

    // CSV only: every sign-in is unknown, and the availability says so.
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&scenario, &opts(5), dir.path()).unwrap();
    for p in json_twins(dir.path()) {
        std::fs::remove_file(p).unwrap();
    }
    let case = ingest_generated(dir.path(), &m);
    let (total, unknown) = counts(&case);
    assert!(total > 0);
    assert_eq!(unknown, total, "a CSV row has no result and says so");
    let note = signin_note(&case);
    assert!(note.contains("no result"), "{note}");
}
