use sparrow_synth::check::check;
use sparrow_synth::generate::{generate, generate_to_dir, generate_with_policy};
use sparrow_synth::options::{Collector, Culture, GenerateOptions, PsEdition, UalFormat};
use sparrow_synth::reserved::scan_text;
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::testing::ingest_generated;
use sparrow_synth::tree::{CulturePolicy, MemSink};

fn opts(seed: u64) -> GenerateOptions {
    GenerateOptions::new(Collector::Invictus, seed)
}

fn green(name: &str, o: &GenerateOptions) -> sparrow_synth::manifest::Manifest {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load(name).unwrap(), o, dir.path()).unwrap();
    let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(report.ok, "{name} {o:?}: {:#?}", report.problems);
    m
}

#[test]
fn every_builtin_checks_green_on_ps7_and_ps51() {
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for ps in [PsEdition::Ps7, PsEdition::Ps51] {
            let mut o = opts(21);
            o.ps = ps;
            green(name, &o);
        }
    }
}

#[test]
fn every_get_ual_format_checks_green() {
    for f in UalFormat::ALL {
        let mut o = opts(22);
        o.ual_format = *f;
        let m = green("bec-aitm", &o);
        assert!(
            m.files.iter().any(|x| x.artifact_id.as_deref() == Some("inv.ual.window")
                && x.status == "parsed"),
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
    // A one-week window before the 13th whose tenant-created dates (400 days earlier, which
    // the Admins/AllRoles files now carry) are also all ambiguous: no culture date can prove
    // the order.
    let mut s = load("business-basic").unwrap();
    s.window.start = "2025-01-04T00:00:00Z".parse().unwrap();
    s.window.days = 7;
    s.window.collected_at = "2025-01-12T10:00:00Z".parse().unwrap();
    s.storylines.clear();
    s.lookalikes.clear();
    let mut o = opts(24);
    o.culture = Culture::EnGb;
    let mut sink = MemSink::default();
    let failing = generate_with_policy(&s, &o, &mut sink, CulturePolicy::Never).unwrap();
    assert!(failing.files.iter().any(|f| f.status == "error"));
    let mut sink = MemSink::default();
    let auto = generate(&s, &o, &mut sink).unwrap();
    assert_eq!(auto.ingest_culture.as_deref(), Some("en-GB"));
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

#[test]
fn non_windows_log_sits_beside_output_and_the_project_is_the_collection() {
    let mut o = opts(28);
    o.non_windows = true;
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load("business-basic").unwrap(), &o, dir.path()).unwrap();
    assert_eq!(m.root, "Output/Adatum_Example");
    let log = std::fs::read(dir.path().join("Output\\LogFile.txt")).unwrap();
    assert!(log.starts_with(b"20") && !log.windows(2).any(|w| w == b"\r\n"));
    assert!(!m.files.iter().any(|f| f.rel_path.ends_with("LogFile.txt")));
    let trace = m
        .files
        .iter()
        .find(|f| f.artifact_id.as_deref() == Some("inv.message_trace"))
        .unwrap();
    let bytes = std::fs::read(dir.path().join(&m.root).join(&trace.rel_path)).unwrap();
    assert!(!bytes.windows(2).any(|w| w == b"\r\n"), "LF line ends");
    let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
}
