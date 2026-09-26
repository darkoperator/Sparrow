use sparrow_synth::check::check;
use sparrow_synth::generate::{generate, generate_to_dir, generate_zip};
use sparrow_synth::options::{Collector, GenerateOptions, SigninExport};
use sparrow_synth::reserved::scan_text;
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::testing::ingest_generated;
use sparrow_synth::tree::MemSink;

fn opts(seed: u64) -> GenerateOptions {
    GenerateOptions::new(Collector::Portal, seed)
}

#[test]
fn same_seed_gives_byte_identical_trees() {
    let s = load("bec-aitm").unwrap();
    let (mut a, mut b) = (MemSink::default(), MemSink::default());
    let ma = generate(&s, &opts(42), &mut a).unwrap();
    let mb = generate(&s, &opts(42), &mut b).unwrap();
    assert_eq!(a.files, b.files);
    assert_eq!(ma.to_json_pretty(), mb.to_json_pretty());
}

#[test]
fn another_seed_changes_the_tree() {
    let s = load("bec-aitm").unwrap();
    let (mut a, mut b) = (MemSink::default(), MemSink::default());
    generate(&s, &opts(42), &mut a).unwrap();
    generate(&s, &opts(43), &mut b).unwrap();
    assert_ne!(a.files, b.files);
}

#[test]
fn generated_trees_contain_only_reserved_values() {
    for name in builtin_names() {
        let mut sink = MemSink::default();
        generate(&load(name).unwrap(), &opts(7), &mut sink).unwrap();
        for (rel, bytes) in &sink.files {
            if rel.ends_with(".mmdb") || rel.ends_with(".xlsx") {
                continue;
            }
            let text = sparrow_core::readers::text::decode(bytes).text;
            let found = scan_text(&text);
            assert!(found.is_empty(), "{name} {rel}: {found:?}");
        }
    }
}

#[test]
fn portal_tree_checks_green() {
    for name in ["bec-aitm", "hawk-investigate", "business-basic"] {
        let dir = tempfile::tempdir().unwrap();
        let m = generate_to_dir(&load(name).unwrap(), &opts(11), dir.path()).unwrap();
        let case = ingest_generated(dir.path(), &m);
        let report = check(&m, &case).unwrap();
        assert!(report.ok, "{name}: {:#?}", report.problems);
    }
}

#[test]
fn xlsx_signin_export_checks_green() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(3);
    o.signin_export = SigninExport::Xlsx;
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &o, dir.path()).unwrap();
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.ends_with(".xlsx") && f.status == "parsed")
    );
    let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
}

#[test]
fn check_reports_missing_extra_and_wrong_status() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(5), dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &m);
    // Tamper with the manifest three ways; each must be reported.
    let t = m.tables.get_mut("ual_events").unwrap();
    t.keys.pop();
    t.keys.push("00000000-0000-4000-8000-000000000000".into());
    t.keys_sha256 = None;
    m.files[0].status = "error".into();
    m.capabilities.insert(
        "audit_premium".into(),
        sparrow_synth::manifest::CapExpect {
            status: "not_licensed".into(),
            confidence: Some("high".into()),
        },
    );
    let report = check(&m, &case).unwrap();
    assert!(!report.ok);
    let all = report.problems.join("\n");
    assert!(
        all.contains("ual_events") && all.contains("missing") && all.contains("extra"),
        "{all}"
    );
    assert!(all.contains(&m.files[0].rel_path), "{all}");
    assert!(all.contains("audit_premium"), "{all}");
}

#[test]
fn zip_is_byte_identical_across_runs() {
    let s = load("bec-aitm").unwrap();
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (_, z1) = generate_zip(&s, &opts(9), &d1.path().join("t")).unwrap();
    let (_, z2) = generate_zip(&s, &opts(9), &d2.path().join("t")).unwrap();
    assert_eq!(std::fs::read(z1).unwrap(), std::fs::read(z2).unwrap());
}

#[test]
fn portal_files_follow_the_export_encodings() {
    let mut sink = MemSink::default();
    let m = generate(&load("bec-aitm").unwrap(), &opts(2), &mut sink).unwrap();
    let file = |prefix: &str| {
        let (rel, bytes) = sink
            .files
            .iter()
            .find(|(rel, _)| {
                rel.strip_prefix(&format!("{}/", m.root))
                    .is_some_and(|r| r.starts_with(prefix))
            })
            .unwrap_or_else(|| panic!("{prefix}"));
        (rel.clone(), bytes.clone())
    };
    // Purview: UTF-8 without BOM, CRLF, 7-digit CreationDate, numeric RecordType.
    let purview = sink
        .files
        .iter()
        .find(|(rel, b)| rel.starts_with(&m.root) && b.starts_with(b"RecordId,"))
        .map(|(_, b)| String::from_utf8(b.clone()).unwrap())
        .unwrap();
    let mut lines = purview.split("\r\n");
    assert_eq!(
        lines.next().unwrap(),
        "RecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits,AssociatedAdminUnitsNames"
    );
    let row = lines.next().unwrap();
    let date = row.split(',').nth(1).unwrap();
    assert_eq!(date.len(), "2026-08-01T10:20:30.0000000Z".len(), "{row}");
    assert!(
        row.split(',').nth(2).unwrap().parse::<u32>().is_ok(),
        "{row}"
    );
    assert!(
        !purview.contains("\r\n\n")
            && purview.matches('\n').count() == purview.matches("\r\n").count()
    );
    // Entra sign-ins: UTF-8 with BOM, LF only.
    let (_, signins) = file("InteractiveSignIns_2026-08-01_2026-09-09.csv");
    assert!(signins.starts_with(&[0xEF, 0xBB, 0xBF]));
    assert!(!signins.contains(&b'\r'));
    let text = String::from_utf8(signins[3..].to_vec()).unwrap();
    assert!(text.starts_with("Date (UTC),Request ID,User agent,"));
    assert!(
        text.lines()
            .next()
            .unwrap()
            .contains(",Autonomous system  number,")
    );
    // Message trace summary: UTF-16LE without BOM, quoted header, CRLF.
    let (_, mt) = file("MTSummary_Message trace report - _2026-09-10T141500.000Z__");
    assert_eq!(&mt[..4], &[b'"', 0, b'o', 0]);
    let units: Vec<u16> = mt
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16(&units).unwrap();
    assert!(text.starts_with("\"origin_timestamp_utc\",\"sender_address\",\"recipient_status\""));
    assert!(text.contains("##"));
    assert_eq!(text.matches('\n').count(), text.matches("\r\n").count());
}

#[test]
fn xlsx_export_is_deterministic() {
    let s = load("business-basic").unwrap();
    let mut o = opts(8);
    o.signin_export = SigninExport::Xlsx;
    let (mut a, mut b) = (MemSink::default(), MemSink::default());
    generate(&s, &o, &mut a).unwrap();
    generate(&s, &o, &mut b).unwrap();
    assert!(a.files.keys().any(|k| k.ends_with(".xlsx")));
    assert_eq!(a.files, b.files);
}

#[test]
fn check_reports_a_moved_sighting() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(6), dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &m);
    let landed = m
        .storylines
        .iter_mut()
        .flat_map(|s| s.evidence.iter_mut())
        .flat_map(|e| e.delivered.iter_mut())
        .next()
        .expect("a delivered sighting");
    landed.sighting.line_start += 1;
    landed.sighting.line_end += 1;
    let key = landed.record_key.clone().unwrap();
    let report = check(&m, &case).unwrap();
    assert!(!report.ok);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("provenance") && p.contains(&key)),
        "{:#?}",
        report.problems
    );
}

#[test]
fn check_reports_hash_count_capability_and_unlisted_sighting_problems() {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(12), dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &m);
    assert!(check(&m, &case).unwrap().ok);
    assert!(m.tenant.domains.contains(&"contoso.example".to_string()));

    // Hashed path: no listed keys, one hex digit of the hash flipped.
    let mut hashed = m.clone();
    let t = hashed.tables.get_mut("ual_events").unwrap();
    t.keys.clear();
    let mut h = t.keys_sha256.clone().unwrap().into_bytes();
    h[0] = if h[0] == b'0' { b'1' } else { b'0' };
    t.keys_sha256 = Some(String::from_utf8(h).unwrap());
    let r = check(&hashed, &case).unwrap();
    assert!(
        r.problems
            .iter()
            .any(|p| p.starts_with("table ual_events") && p.contains("hash")),
        "{:#?}",
        r.problems
    );

    // Row count: one row more than the keys.
    let mut counted = m.clone();
    counted.tables.get_mut("signins").unwrap().rows += 1;
    let r = check(&counted, &case).unwrap();
    assert!(
        r.problems
            .iter()
            .any(|p| p.starts_with("table signins") && p.contains("rows, expected")),
        "{:#?}",
        r.problems
    );

    // A listed capability with the wrong status: the mismatch branch, not "missing".
    let mut cap = m.clone();
    let c = cap.capabilities.get_mut("ual_standard").unwrap();
    assert_eq!(c.status, "licensed");
    c.status = "not_licensed".into();
    let r = check(&cap, &case).unwrap();
    assert!(
        r.problems
            .iter()
            .any(|p| p.starts_with("capability ual_standard: licensed/")
                && p.contains("expected not_licensed")),
        "{:#?}",
        r.problems
    );

    // A sighting in a file the manifest does not list.
    let mut moved = m.clone();
    let landed = moved
        .storylines
        .iter_mut()
        .flat_map(|s| s.evidence.iter_mut())
        .flat_map(|e| e.delivered.iter_mut())
        .next()
        .unwrap();
    landed.sighting.rel_path = "nowhere.csv".into();
    let r = check(&moved, &case).unwrap();
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("nowhere.csv") && p.contains("not in the manifest")),
        "{:#?}",
        r.problems
    );
}
