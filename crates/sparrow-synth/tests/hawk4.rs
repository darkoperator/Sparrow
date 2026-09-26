use sparrow_synth::check::check;
use sparrow_synth::generate::{generate, generate_to_dir};
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::reserved::scan_text;
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::testing::ingest_generated;
use sparrow_synth::tree::MemSink;

fn opts(seed: u64) -> GenerateOptions {
    GenerateOptions::new(Collector::Hawk4, seed)
}

fn green(name: &str, o: &GenerateOptions) -> sparrow_synth::manifest::Manifest {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load(name).unwrap(), o, dir.path()).unwrap();
    let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(report.ok, "{name} {o:?}: {:#?}", report.problems);
    m
}

#[test]
fn every_builtin_checks_green_across_editions() {
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for (ps, mixed) in [
            (PsEdition::Ps7, false),
            (PsEdition::Ps51, false),
            (PsEdition::Ps7, true),
        ] {
            let mut o = opts(31);
            o.ps = ps;
            o.hawk_mixed_editions = mixed;
            green(name, &o);
        }
    }
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
