use sparrow_synth::check::check;
use sparrow_synth::generate::{generate, generate_to_dir};
use sparrow_synth::options::{Collector, Culture, GenerateOptions, PsEdition};
use sparrow_synth::reserved::scan_text;
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::testing::ingest_generated;
use sparrow_synth::tree::MemSink;

fn opts(seed: u64) -> GenerateOptions {
    GenerateOptions::new(Collector::Hawk3, seed)
}

fn green(name: &str, o: &GenerateOptions) -> sparrow_synth::manifest::Manifest {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load(name).unwrap(), o, dir.path()).unwrap();
    let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(report.ok, "{name} {o:?}: {:#?}", report.problems);
    m
}

/// Every built-in scenario but `volume`.
const MATRIX: &[&str] = &[
    "audit-tamper",
    "bec-aitm",
    "bec-e3-audit-gaps",
    "bec-o365-no-p1",
    "business-basic",
    "hawk-investigate",
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

/// One test per scenario × (edition, culture), so the harness runs them in parallel.
macro_rules! green_matrix {
    ($($test:ident: $scenario:literal, $ps:expr, $culture:expr;)+) => {
        $(
            #[test]
            fn $test() {
                let mut o = opts(41);
                o.ps = $ps;
                o.culture = $culture;
                green($scenario, &o);
            }
        )+
    };
}

green_matrix! {
    audit_tamper_ps51_en_us: "audit-tamper", PsEdition::Ps51, Culture::EnUs;
    audit_tamper_ps7_en_us: "audit-tamper", PsEdition::Ps7, Culture::EnUs;
    audit_tamper_ps51_en_gb: "audit-tamper", PsEdition::Ps51, Culture::EnGb;
    bec_aitm_ps51_en_us: "bec-aitm", PsEdition::Ps51, Culture::EnUs;
    bec_aitm_ps7_en_us: "bec-aitm", PsEdition::Ps7, Culture::EnUs;
    bec_aitm_ps51_en_gb: "bec-aitm", PsEdition::Ps51, Culture::EnGb;
    bec_e3_audit_gaps_ps51_en_us: "bec-e3-audit-gaps", PsEdition::Ps51, Culture::EnUs;
    bec_e3_audit_gaps_ps7_en_us: "bec-e3-audit-gaps", PsEdition::Ps7, Culture::EnUs;
    bec_e3_audit_gaps_ps51_en_gb: "bec-e3-audit-gaps", PsEdition::Ps51, Culture::EnGb;
    bec_o365_no_p1_ps51_en_us: "bec-o365-no-p1", PsEdition::Ps51, Culture::EnUs;
    bec_o365_no_p1_ps7_en_us: "bec-o365-no-p1", PsEdition::Ps7, Culture::EnUs;
    bec_o365_no_p1_ps51_en_gb: "bec-o365-no-p1", PsEdition::Ps51, Culture::EnGb;
    business_basic_ps51_en_us: "business-basic", PsEdition::Ps51, Culture::EnUs;
    business_basic_ps7_en_us: "business-basic", PsEdition::Ps7, Culture::EnUs;
    business_basic_ps51_en_gb: "business-basic", PsEdition::Ps51, Culture::EnGb;
    hawk_investigate_ps51_en_us: "hawk-investigate", PsEdition::Ps51, Culture::EnUs;
    hawk_investigate_ps7_en_us: "hawk-investigate", PsEdition::Ps7, Culture::EnUs;
    hawk_investigate_ps51_en_gb: "hawk-investigate", PsEdition::Ps51, Culture::EnGb;
}

#[test]
fn admin_activity_uses_the_admin_audit_shape() {
    let mut sink = MemSink::default();
    let m = generate(&load("hawk-investigate").unwrap(), &opts(42), &mut sink).unwrap();
    let f = m
        .files
        .iter()
        .find(|f| f.rel_path == "Tenant/New_InboxRules.json")
        .unwrap();
    assert_eq!(f.status, "parsed");
    assert!(m.tables["admin_audit_events"].rows > 0);
    let bytes = &sink
        .files
        .iter()
        .find(|(k, _)| k.ends_with("Tenant/New_InboxRules.json"))
        .unwrap()
        .1;
    let text = sparrow_core::readers::text::decode(bytes).text;
    assert!(text.contains("CmdletParameters") && text.contains("RunDate"));
}

#[test]
fn clixml_and_forwarding_recipients_are_recorded_but_not_loaded() {
    let mut sink = MemSink::default();
    let m = generate(&load("bec-aitm").unwrap(), &opts(43), &mut sink).unwrap();
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.starts_with("Tenant/XML/") && f.status == "not_supported")
    );
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.starts_with("Tenant/Forwarding_Recipients"))
    );
}

#[test]
fn the_log_uses_the_host_culture_and_the_hawk3_dialect() {
    let mut o = opts(44);
    o.ps = PsEdition::Ps51;
    o.culture = Culture::EnGb;
    let mut sink = MemSink::default();
    let m = generate(&load("hawk-investigate").unwrap(), &o, &mut sink).unwrap();
    let log = &sink
        .files
        .iter()
        .find(|(k, _)| k.ends_with("/Hawk.log"))
        .unwrap()
        .1;
    assert_eq!(&log[..2], &[0xFF, 0xFE], "5.1 writes the log UTF-16LE");
    let text = sparrow_core::readers::text::decode(log).text;
    assert!(text.contains("*** Version 3.1.0 ***"));
    // en-GB `G`: dd/MM/yyyy HH:mm:ss (collected 2026-09-04 11:00 UTC, host on UTC).
    assert!(
        text.starts_with("[04/09/2026 11:00:00] - "),
        "{}",
        &text[..80]
    );
    assert!(!text.contains("License type detected"));
    let log_file = m.files.iter().find(|f| f.rel_path == "Hawk.log").unwrap();
    assert!(log_file.date_evidence.is_some_and(|e| e.culture_dates > 0));
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.ends_with("_logs.csv") && f.encoding == "utf-8-bom")
    );
}

#[test]
fn trees_are_deterministic_and_clean() {
    let s = load("hawk-investigate").unwrap();
    let mut o = opts(45);
    o.ps = PsEdition::Ps51;
    let (mut a, mut b) = (MemSink::default(), MemSink::default());
    generate(&s, &o, &mut a).unwrap();
    generate(&s, &o, &mut b).unwrap();
    assert_eq!(a.files, b.files);
    // PowerShell 7 does not wrap Format-List values, so no domain is split across lines.
    o.ps = PsEdition::Ps7;
    let mut a = MemSink::default();
    generate(&s, &o, &mut a).unwrap();
    for (rel, bytes) in &a.files {
        if rel.ends_with(".mmdb") {
            continue;
        }
        let found = scan_text(&sparrow_core::readers::text::decode(bytes).text);
        assert!(found.is_empty(), "{rel}: {found:?}");
    }
}
