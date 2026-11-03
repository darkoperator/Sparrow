//! The oracle for the streaming-ingest refactor: a deterministic dump of every ingested row over
//! generated collector trees. `record_stream_baseline` writes one JSON per tree into
//! `$SPARROW_STREAM_BASELINE`; `compare_stream_baseline` re-ingests and compares table by table.
//! Both are ignored (run on demand, record on the commit before the refactor).
//!
//! `crates/sparrow-core/tests/` has no fixture files for ingest (its tests build their inputs
//! inline), so the generated trees below are the whole corpus.

use sparrow_core::Case;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::readers::time::parse_culture;
use sparrow_synth::case_dump::dump_case;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{
    Collector, Culture, GenerateOptions, PsEdition, SigninExport, UalFormat,
};
use sparrow_synth::scenario::load;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

type Dump = BTreeMap<String, Vec<String>>;

/// One generated tree: a name (the baseline file stem), a scenario and the options.
fn trees() -> Vec<(String, &'static str, GenerateOptions)> {
    let mut v = Vec::new();
    let mut add = |name: &str, scenario: &'static str, o: GenerateOptions| {
        v.push((name.to_string(), scenario, o));
    };
    add(
        "hawk3-bec-aitm",
        "bec-aitm",
        GenerateOptions::new(Collector::Hawk3, 41),
    );
    let mut o = GenerateOptions::new(Collector::Hawk3, 42);
    o.ps = PsEdition::Ps51;
    o.culture = Culture::DeDe;
    add("hawk3-audit-tamper-ps51-de", "audit-tamper", o);
    add(
        "hawk4-bec-aitm",
        "bec-aitm",
        GenerateOptions::new(Collector::Hawk4, 43),
    );
    let mut o = GenerateOptions::new(Collector::Hawk4, 44);
    o.hawk_mixed_editions = true;
    add("hawk4-password-spray-mixed", "password-spray", o);
    add(
        "invictus-bec-aitm",
        "bec-aitm",
        GenerateOptions::new(Collector::Invictus, 45),
    );
    for f in UalFormat::ALL {
        let mut o = GenerateOptions::new(Collector::Invictus, 46);
        o.ual_format = *f;
        add(&format!("invictus-ual-{f}"), "bec-e3-audit-gaps", o);
    }
    let mut o = GenerateOptions::new(Collector::Invictus, 47);
    o.non_windows = true;
    o.invictus_devices_json = true;
    add("invictus-nonwindows-devices-json", "business-basic", o);
    add(
        "portal-bec-aitm",
        "bec-aitm",
        GenerateOptions::new(Collector::Portal, 48),
    );
    let mut o = GenerateOptions::new(Collector::Portal, 49);
    o.signin_export = SigninExport::Xlsx;
    o.message_trace_excel_resave = Some(true);
    add("portal-password-spray-xlsx", "password-spray", o);
    v
}

/// Ingest `dir/<manifest root>` into a fresh in-memory case with no file-size limit and dump it.
fn ingest_dump(dir: &Path, manifest: &sparrow_synth::manifest::Manifest) -> Dump {
    let mut case = Case::in_memory().expect("in-memory case");
    let date_order = manifest
        .ingest_culture
        .as_deref()
        .map(|c| parse_culture(c).expect("ingest_culture"));
    let opts = IngestOptions {
        max_file_bytes: u64::MAX,
        date_order,
        ..IngestOptions::default()
    };
    ingest_path(
        &mut case,
        &dir.join(&manifest.root),
        &ParserRegistry::builtin(),
        &opts,
    )
    .unwrap_or_else(|e| panic!("ingest failed: {e}"));
    dump_case(&case).expect("dump")
}

fn generate_and_dump(scenario: &str, o: &GenerateOptions) -> Dump {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("tree");
    let manifest = generate_to_dir(&load(scenario).unwrap(), o, &dir).expect("generate");
    ingest_dump(&dir, &manifest)
}

fn baseline_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("SPARROW_STREAM_BASELINE")
            .expect("set SPARROW_STREAM_BASELINE to the baseline directory"),
    )
}

/// Table-by-table differences between `want` and `got`: each message names the table, the row
/// counts and the first 5 rows missing (`-`) and extra (`+`).
fn differences(name: &str, want: &Dump, got: &Dump) -> Vec<String> {
    let mut out = Vec::new();
    let tables: std::collections::BTreeSet<&String> = want.keys().chain(got.keys()).collect();
    for t in tables {
        let empty = Vec::new();
        let (w, g) = (want.get(t).unwrap_or(&empty), got.get(t).unwrap_or(&empty));
        if w == g {
            continue;
        }
        let mut msg = format!(
            "{name}/{t}: baseline {} rows, now {} rows",
            w.len(),
            g.len()
        );
        let missing: Vec<&String> = w.iter().filter(|r| !g.contains(r)).take(5).collect();
        let extra: Vec<&String> = g.iter().filter(|r| !w.contains(r)).take(5).collect();
        for r in missing {
            msg.push_str(&format!("\n  - {}", r.replace('\u{1f}', " | ")));
        }
        for r in extra {
            msg.push_str(&format!("\n  + {}", r.replace('\u{1f}', " | ")));
        }
        out.push(msg);
    }
    out
}

#[test]
fn dump_is_stable_across_two_ingests() {
    let o = GenerateOptions::new(Collector::Hawk3, 41);
    let a = generate_and_dump("bec-aitm", &o);
    let b = generate_and_dump("bec-aitm", &o);
    assert!(
        a["record_sources"].len() > 100 && !a["source_files"].is_empty(),
        "the dump must carry ingested rows"
    );
    assert!(
        a.iter().filter(|(_, r)| !r.is_empty()).count() >= 5,
        "several evidence tables must have rows"
    );
    let diff = differences("tree", &a, &b);
    assert!(diff.is_empty(), "{}", diff.join("\n"));
}

#[test]
#[ignore = "records the baseline; needs SPARROW_STREAM_BASELINE"]
fn record_stream_baseline() {
    let dir = baseline_dir();
    std::fs::create_dir_all(&dir).unwrap();
    for (name, scenario, o) in trees() {
        let d = generate_and_dump(scenario, &o);
        let rows: usize = d.values().map(Vec::len).sum();
        assert!(!d["record_sources"].is_empty(), "{name}: no record_sources");
        std::fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_vec(&d).unwrap(),
        )
        .unwrap();
        eprintln!("recorded {name}: {} tables, {rows} rows", d.len());
    }
}

#[test]
#[ignore = "compares to the recorded baseline; needs SPARROW_STREAM_BASELINE"]
fn compare_stream_baseline() {
    let dir = baseline_dir();
    let mut failures = Vec::new();
    for (name, scenario, o) in trees() {
        let path = dir.join(format!("{name}.json"));
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "no baseline {}: {e} (run record_stream_baseline)",
                path.display()
            )
        });
        let want: Dump = serde_json::from_slice(&bytes).unwrap();
        let got = generate_and_dump(scenario, &o);
        for msg in differences(&name, &want, &got) {
            eprintln!("{msg}");
            failures.push(msg);
        }
    }
    assert!(
        failures.is_empty(),
        "{} table(s) differ from the baseline",
        failures.len()
    );
}
