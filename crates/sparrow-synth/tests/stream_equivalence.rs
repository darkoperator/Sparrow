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

const EDGE_TREE: &str = "invictus-edge-encodings";
const LARGE_TREE: &str = "invictus-large-files";

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
    // Encodings, line endings and broken records (see `mutate_edge`); same tree, mutated copies.
    add(
        EDGE_TREE,
        "bec-aitm",
        GenerateOptions::new(Collector::Invictus, 50),
    );
    // UAL and sign-in files above 20 MB, to cross streaming buffer edges.
    let mut o = GenerateOptions::new(Collector::Invictus, 51);
    o.ual_rows = Some(15_000);
    o.signins = Some(12_000);
    add(LARGE_TREE, "bec-aitm", o);
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
        max_file_bytes: None,
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

fn generate_and_dump(name: &str, scenario: &str, o: &GenerateOptions) -> Dump {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("tree");
    let manifest = generate_to_dir(&load(scenario).unwrap(), o, &dir).expect("generate");
    if name == EDGE_TREE {
        mutate_edge(&dir.join(&manifest.root));
    }
    if name == LARGE_TREE {
        let big: Vec<String> = walk(&dir)
            .into_iter()
            .filter(|p| std::fs::metadata(p).unwrap().len() > 20 << 20)
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        eprintln!("{name}: files over 20 MB: {big:#?}");
        assert!(
            big.iter().any(|p| p.contains("UnifiedAuditLog")),
            "{name}: no UAL file over 20 MB"
        );
        assert!(
            big.iter().any(|p| p.contains("Sign-In")),
            "{name}: no sign-ins file over 20 MB"
        );
    }
    ingest_dump(&dir, &manifest)
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// The one file under `root` whose path ends with `suffix`.
fn find(root: &Path, suffix: &str) -> PathBuf {
    let hits: Vec<PathBuf> = walk(root)
        .into_iter()
        .filter(|p| p.to_string_lossy().replace('\\', "/").ends_with(suffix))
        .collect();
    assert_eq!(hits.len(), 1, "{suffix}: expected one file, found {hits:?}");
    hits.into_iter().next().unwrap()
}

fn utf16(text: &str, big_endian: bool, bom: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut put = |u: u16| {
        out.extend(if big_endian {
            u.to_be_bytes()
        } else {
            u.to_le_bytes()
        });
    };
    if bom {
        put(0xFEFF);
    }
    text.encode_utf16().for_each(&mut put);
    out
}

/// Windows-1252 bytes of `text` (ASCII, e-acute and the euro sign only).
fn cp1252(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| match c {
            '\u{e9}' => 0xE9,
            '\u{20ac}' => 0x80,
            c if c.is_ascii() => c as u8,
            c => panic!("not cp1252: {c}"),
        })
        .collect()
}

/// `text`'s last data row with its first field replaced by `first` (quoted).
fn cloned_last_row(text: &str, first: &str) -> String {
    let last = text.trim_end().lines().last().unwrap();
    let rest = if let Some(q) = last.strip_prefix('"') {
        &q[q.find("\",").expect("quoted first field") + 1..]
    } else {
        &last[last.find(',').expect("comma")..]
    };
    format!("\"{first}\"{rest}")
}

/// Rewrite recognised files of an Extractor-Suite tree so the oracle sees every decoder branch,
/// a CRLF file with a quoted embedded newline, a malformed CSV row and broken JSON records.
/// File names are kept, so each still classifies as before.
fn mutate_edge(root: &Path) {
    let text = |p: &Path| String::from_utf8(std::fs::read(p).unwrap()).unwrap();
    // Encodings.
    let p = find(root, "-Users.csv");
    std::fs::write(&p, utf16(&text(&p), false, true)).unwrap();
    let p = find(root, "-SecureScore.csv");
    std::fs::write(&p, utf16(&text(&p), true, true)).unwrap();
    let p = find(root, "-ConditionalAccessPolicies.csv");
    std::fs::write(&p, utf16(&text(&p), false, false)).unwrap();
    let p = find(root, "-PIM-Assignments.csv");
    std::fs::write(&p, [&[0xEF, 0xBB, 0xBF][..], text(&p).as_bytes()].concat()).unwrap();
    let p = find(root, "-SecurityAlerts.csv");
    let t = text(&p);
    let row = cloned_last_row(&t, "Caf\u{e9} \u{20ac}5");
    std::fs::write(&p, cp1252(&format!("{}\n{row}\n", t.trim_end()))).unwrap();
    let p = find(root, "Triage-Contoso_Example/Set-Mailbox.json");
    std::fs::write(&p, utf16(&text(&p), false, true)).unwrap();
    let p = find(root, "Triage-Contoso_Example/Consent to application_.json");
    std::fs::write(&p, [&[0xEF, 0xBB, 0xBF][..], text(&p).as_bytes()].concat()).unwrap();
    // CRLF with a quoted field holding a newline.
    let p = find(root, "-UserApplications.csv");
    let t = text(&p).replace("\r\n", "\n");
    let row = cloned_last_row(&t, "line one\r\nline two");
    let crlf = format!("{}\n{row}\n", t.trim_end()).replace('\n', "\r\n");
    // the embedded newline must stay a bare CRLF inside the quotes: the replace above made it \r\r\n
    std::fs::write(&p, crlf.replace("\r\r\n", "\r\n")).unwrap();
    // A malformed row (unterminated quote) in the middle of a CSV.
    let p = find(root, "DirectoryActivityLogs.csv");
    let t = text(&p);
    let mut lines: Vec<&str> = t.lines().collect();
    assert!(
        lines.len() >= 3,
        "directory activity too short to break mid-file"
    );
    let mid = lines.len() / 2;
    lines.insert(mid, "\"unterminated,field,\"x");
    std::fs::write(&p, lines.join("\n") + "\n").unwrap();
    // JSON: a broken record in the middle of an array, then a record over 500 characters that
    // does not parse (so the snippet is cut at 500).
    let p = find(root, "Triage-Contoso_Example/New-InboxRule.json");
    let v: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    assert!(v.len() >= 3);
    let mut parts: Vec<String> = v
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    parts.insert(
        1,
        "{\"RecordType\": \"ExchangeAdmin\", \"UserIds\": }".to_string(),
    );
    let long = format!("{{\"Operations\": \"{}\" \"Broken\": 1}}", "x".repeat(900));
    parts.insert(3, long);
    std::fs::write(&p, format!("[\n{}\n]\n", parts.join(",\n"))).unwrap();
}

fn baseline_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("SPARROW_STREAM_BASELINE")
            .expect("set SPARROW_STREAM_BASELINE to the baseline directory"),
    )
}

fn count(v: &[String]) -> std::collections::HashMap<&String, usize> {
    let mut m = std::collections::HashMap::new();
    for r in v {
        *m.entry(r).or_default() += 1;
    }
    m
}

/// Table-by-table differences between `want` and `got`: each message names the table, the row
/// counts and the first 5 rows missing (`-`), extra (`+`) or present a different number of
/// times (`~`).
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
        let (wc, gc) = (count(w), count(g));
        let missing: Vec<&String> = w.iter().filter(|r| !gc.contains_key(r)).take(5).collect();
        let extra: Vec<&String> = g.iter().filter(|r| !wc.contains_key(r)).take(5).collect();
        let mut dup: Vec<String> = wc
            .iter()
            .filter(|(r, n)| gc.get(*r).is_some_and(|m| m != *n))
            .take(5)
            .map(|(r, n)| format!("  ~ x{n} -> x{}: {}", gc[*r], r.replace('\u{1f}', " | ")))
            .collect();
        dup.sort();
        for r in missing {
            msg.push_str(&format!("\n  - {}", r.replace('\u{1f}', " | ")));
        }
        for r in extra {
            msg.push_str(&format!("\n  + {}", r.replace('\u{1f}', " | ")));
        }
        for d in dup {
            msg.push_str(&format!("\n{d}"));
        }
        out.push(msg);
    }
    out
}

#[test]
fn dump_is_stable_across_two_ingests() {
    let o = GenerateOptions::new(Collector::Hawk3, 41);
    let a = generate_and_dump("stable", "bec-aitm", &o);
    let b = generate_and_dump("stable", "bec-aitm", &o);
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
        let d = generate_and_dump(&name, scenario, &o);
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
        let got = generate_and_dump(&name, scenario, &o);
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

#[test]
fn edge_tree_is_stable_and_exercises_the_decoders() {
    let o = GenerateOptions::new(Collector::Invictus, 50);
    let a = generate_and_dump(EDGE_TREE, "bec-aitm", &o);
    let b = generate_and_dump(EDGE_TREE, "bec-aitm", &o);
    let diff = differences("edge", &a, &b);
    assert!(diff.is_empty(), "{}", diff.join("\n"));
    assert!(
        !a["parse_errors"].is_empty(),
        "the edge tree must produce parse errors"
    );
    let mut enc: BTreeMap<String, usize> = BTreeMap::new();
    for r in &a["source_files"] {
        // source_files columns: file_id, collection_id, rel_path, artifact_type, format, encoding
        let c: Vec<&str> = r.split('\u{1f}').collect();
        *enc.entry(c[5].to_string()).or_default() += 1;
    }
    eprintln!(
        "edge encodings: {enc:?}; parse_errors: {}",
        a["parse_errors"].len()
    );
    for (want, n) in [
        ("utf-8", 1),
        ("utf-16le", 3),
        ("utf-16be", 1),
        ("utf-8-bom", 2),
        ("windows-1252", 1),
    ] {
        assert!(
            enc.get(want).copied().unwrap_or(0) >= n,
            "{want} x{n} missing in {enc:?}"
        );
    }
    assert!(
        a["parse_errors"]
            .iter()
            .any(|r| r.rsplit('\u{1f}').next().unwrap().chars().count() == 500),
        "no parse error with a 500-char snippet"
    );
    for r in &a["parse_errors"] {
        eprintln!(
            "parse_error: {}",
            r.replace('\u{1f}', " | ")
                .chars()
                .take(260)
                .collect::<String>()
        );
    }
}
