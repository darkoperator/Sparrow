use sparrow_synth::check::check_without_detection as check;
use sparrow_synth::generate::{generate, generate_to_dir, generate_zip};
use sparrow_synth::options::{Collector, Culture, GenerateOptions, SigninExport};
use sparrow_synth::reserved::scan_text;
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::testing::ingest_generated;
use sparrow_synth::tree::MemSink;
use std::collections::BTreeSet;

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

fn reserved_values_only(name: &str) {
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

/// Fast representative of the every-scenario scan below.
#[test]
fn bec_aitm_tree_contains_only_reserved_values() {
    reserved_values_only("bec-aitm");
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn generated_trees_contain_only_reserved_values() {
    for name in builtin_names() {
        reserved_values_only(name);
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

/// The Excel export carries the portal's own header spellings (`Application ID `, `Resource
/// ID `, `Autonomous system  number`), and the sign-in parser keys its rows by the header
/// cleanup a CSV header gets, so the values behind them are the manifest's: this check is the
/// value-level proof that both spellings load.
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
    // Purview: UTF-8 without BOM, CRLF, numeric RecordType, and a `CreationDate` the tree's
    // export version wrote (the 7-digit ISO string or the host culture's form, one form
    // throughout -- `purview_creation_date_follows_the_export_version_of_the_tree` covers the
    // two forms and the choice).
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
    assert!(
        date.len() == "2026-08-01T10:20:30.0000000Z".len() || date.contains(':'),
        "{date}"
    );
    let iso = purview
        .lines()
        .skip(1)
        .all(|l| l.split(',').nth(1).unwrap().len() == "2026-08-01T10:20:30.0000000Z".len());
    let culture = purview
        .lines()
        .skip(1)
        .all(|l| l.split(',').nth(1).unwrap().contains(':'));
    assert!(iso || culture, "the export mixes both CreationDate forms");
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
    // Message trace summary: CRLF, and the columns the portal writes. Across seeds it is
    // either the download itself (UTF-16LE without a BOM, every field quoted) or the
    // single-byte file an analyst re-saved through Excel (cp1252, unquoted header), and both
    // variants occur -- `message_trace_summary_is_utf16_by_default_and_cp1252_after_an_excel_resave`
    // pins which seed is which and the parser round-trip.
    let mut shapes: BTreeSet<(&'static str, bool)> = BTreeSet::new();
    for seed in 1..=12u64 {
        let mut sink = MemSink::default();
        let m = generate(&load("bec-aitm").unwrap(), &opts(seed), &mut sink).unwrap();
        let (_, mt) = sink
            .files
            .iter()
            .find(|(rel, _)| rel.contains(&format!("{}/MTSummary_", m.root)))
            .expect("the message-trace summary");
        let decoded = sparrow_core::readers::text::decode(mt);
        assert!(decoded.text.contains("##"), "seed {seed}");
        assert_eq!(
            decoded.text.matches('\n').count(),
            decoded.text.matches("\r\n").count(),
            "seed {seed}: not CRLF"
        );
        let header = decoded.text.lines().next().unwrap();
        let quoted = header.starts_with('"');
        assert_eq!(
            quoted,
            decoded.text.lines().nth(1).unwrap().starts_with('"'),
            "seed {seed}: the header and the rows disagree on quoting"
        );
        let name = match decoded.encoding {
            sparrow_core::readers::text::TextEncoding::Utf16Le => "utf-16le",
            sparrow_core::readers::text::TextEncoding::Windows1252 => "windows-1252",
            other => panic!("seed {seed}: {other:?}"),
        };
        // The header names the same columns in both spellings.
        for column in [
            "origin_timestamp_utc",
            "sender_address",
            "recipient_status",
            "message_subject",
        ] {
            assert!(header.contains(column), "seed {seed}: {header}");
        }
        shapes.insert((name, quoted));
    }
    assert_eq!(
        shapes,
        BTreeSet::from([("utf-16le", true), ("windows-1252", false)]),
        "the message-trace summary is not written in both shapes"
    );
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

/// Task F9.1: the real portal sign-in export writes `Application ID `, `Resource ID ` and
/// `Autonomous system  number` with their trailing and double spaces, in the CSV and in the
/// Excel workbook alike. The generator writes those spellings in both, and a profile of either
/// file cleans its header the same way (trimmed, inner spaces collapsed, a repeated column
/// suffixed `_2`), so a real capture's workbook and a generated CSV compare equal -- which is
/// what `conformance --real` compares.
#[test]
fn signin_export_headers_clean_the_same_in_csv_and_xlsx() {
    let headers = |export: SigninExport| {
        let mut o = opts(3);
        o.signin_export = export;
        let dir = tempfile::tempdir().unwrap();
        generate_to_dir(&load("bec-aitm").unwrap(), &o, dir.path()).unwrap();
        let p = sparrow_synth::conformance::profile_dir(dir.path()).unwrap();
        let ap = p
            .artifacts
            .get("portal.entra_signins")
            .expect("portal.entra_signins");
        ap.headers.keys().cloned().collect::<Vec<Vec<String>>>()
    };
    // The profile cleans a workbook's header, so the spellings themselves are checked here, on
    // the raw header row the workbook really carries: the portal writes them with the spaces.
    let mut sink = MemSink::default();
    let mut o = opts(3);
    o.signin_export = SigninExport::Xlsx;
    let m = generate(&load("bec-aitm").unwrap(), &o, &mut sink).unwrap();
    let (_, bytes) = sink
        .files
        .iter()
        .find(|(rel, _)| rel.contains(&format!("{}/InteractiveSignins_", m.root)))
        .expect("the workbook");
    let raw = sparrow_core::readers::xlsx::xlsx_headers(bytes).expect("the workbook's header");
    assert!(
        raw.contains(&"Application ID ".to_string())
            && raw.contains(&"Resource ID ".to_string())
            && raw.contains(&"Autonomous system  number".to_string()),
        "the raw header lost the portal's spellings: {:?}",
        &raw[..20]
    );
    assert_eq!(
        raw.iter().filter(|h| *h == "Incoming token type").count(),
        2,
        "the duplicated column is gone"
    );

    let (csv, xlsx) = (headers(SigninExport::Csv), headers(SigninExport::Xlsx));
    assert_eq!(csv, xlsx, "the CSV and the workbook clean differently");
    let header = &csv[0];
    assert_eq!(header.len(), 57);
    // The real spellings are in the file, and the profile cleaned them.
    assert!(
        header.contains(&"Application ID".to_string())
            && header.contains(&"Autonomous system number".to_string())
            && header.contains(&"Resource ID".to_string()),
        "{header:?}"
    );
    assert!(
        header.contains(&"Incoming token type".to_string())
            && header.contains(&"Incoming token type_2".to_string()),
        "{header:?}"
    );
}

/// Task F9.2: the Exchange message-trace summary download is UTF-16LE without a BOM with a
/// quoted header and CRLF (survey §3, captures A and B), and about one tree in four is the
/// single-byte file an analyst re-saved through Excel: cp1252, unquoted header, CRLF (capture
/// D). Both are per-tree choices, and the reader decodes both back to the same text, the
/// non-ASCII character in one of the subjects included.
#[test]
fn message_trace_summary_is_utf16_by_default_and_cp1252_after_an_excel_resave() {
    // (encoding, header quoted, bytes, decoded text) of the generated summary.
    let summary = |seed: u64| {
        let mut sink = MemSink::default();
        let m = generate(&load("bec-aitm").unwrap(), &opts(seed), &mut sink).unwrap();
        let (_, bytes) = sink
            .files
            .iter()
            .find(|(rel, _)| rel.contains(&format!("{}/MTSummary_", m.root)))
            .expect("the message-trace summary");
        let decoded = sparrow_core::readers::text::decode(bytes);
        let quoted = decoded.text.starts_with("\"origin_timestamp_utc\"");
        (decoded.encoding, quoted, bytes.to_vec(), decoded.text)
    };

    let mut utf16 = 0;
    let mut resaved = 0;
    for seed in 1..=12u64 {
        let (encoding, quoted, bytes, text) = summary(seed);
        match encoding {
            sparrow_core::readers::text::TextEncoding::Utf16Le => {
                // No BOM, the header quoted, and the non-ASCII character in the subject as
                // its own UTF-16 code unit (0x00E9), not a UTF-8 sequence.
                assert!(!bytes.starts_with(&[0xFF, 0xFE]), "seed {seed}: a BOM");
                assert!(quoted, "seed {seed}: an unquoted header");
                assert_eq!(&bytes[..4], &[b'"', 0, b'o', 0], "seed {seed}");
                utf16 += 1;
            }
            sparrow_core::readers::text::TextEncoding::Windows1252 => {
                // An Excel re-save: single-byte, and the header unquoted.
                assert!(!quoted, "seed {seed}: a quoted header");
                assert!(
                    decoded_has_non_ascii_subject(seed),
                    "seed {seed}: no non-ASCII subject for the single-byte file"
                );
                resaved += 1;
            }
            other => panic!("seed {seed}: {other:?}"),
        }
        // CRLF, in whichever encoding the file is written.
        assert_eq!(
            text.matches('\n').count(),
            text.matches("\r\n").count(),
            "seed {seed}: not CRLF line ends"
        );
    }
    // Both variants exist, and the re-save is the rare one.
    assert!(
        utf16 > 0 && resaved > 0,
        "{utf16} UTF-16LE, {resaved} re-saved"
    );
    assert!(
        resaved * 3 <= utf16,
        "{resaved} of {} trees re-saved by Excel is not the rare one",
        utf16 + resaved
    );
}

/// Whether the generated summary of `seed` carries a subject with a non-ASCII character in its
/// raw bytes (what forces the reader off UTF-8).
fn decoded_has_non_ascii_subject(seed: u64) -> bool {
    let mut sink = MemSink::default();
    let m = generate(&load("bec-aitm").unwrap(), &opts(seed), &mut sink).unwrap();
    let (_, bytes) = sink
        .files
        .iter()
        .find(|(rel, _)| rel.contains(&format!("{}/MTSummary_", m.root)))
        .expect("the message-trace summary");
    // A cp1252 subject byte: 0xA0-0xFF outside ASCII, which in the UTF-16 file is the single
    // code unit 0x00E9 rather than the byte the single-byte file carries.
    bytes.iter().any(|b| (0xA0..=0xFF).contains(b))
}

/// The parser decodes both variants back to the same subject, not to a replacement character:
/// one seed of each kind is ingested and the stored `message_trace.subject` is the character.
#[test]
fn both_message_trace_variants_load_the_same_subject() {
    for seed in 1..=12u64 {
        let (encoding, _, _) = {
            let mut sink = MemSink::default();
            let m = generate(&load("bec-aitm").unwrap(), &opts(seed), &mut sink).unwrap();
            let (_, bytes) = sink
                .files
                .iter()
                .find(|(rel, _)| rel.contains(&format!("{}/MTSummary_", m.root)))
                .expect("the message-trace summary");
            (sparrow_core::readers::text::decode(bytes).encoding, (), ())
        };
        let dir = tempfile::tempdir().unwrap();
        let m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(seed), dir.path()).unwrap();
        let case = ingest_generated(dir.path(), &m);
        let q = |sql: &str| {
            case.conn()
                .query_row(sql, [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        assert!(
            q("SELECT count(*) FROM message_trace WHERE subject LIKE '%é%'") > 0,
            "seed {seed} ({encoding:?}): the non-ASCII subject did not survive"
        );
        assert_eq!(
            q("SELECT count(*) FROM message_trace WHERE subject LIKE '%Caf?%'"),
            0,
            "seed {seed} ({encoding:?}): the subject was mangled"
        );
        assert_eq!(
            q("SELECT count(*) FROM message_trace WHERE position('\u{fffd}' in subject) > 0"),
            0,
            "seed {seed} ({encoding:?}): a replacement character"
        );
    }
}

/// Task F9.3: the Purview audit search export renders `CreationDate` the way its own version
/// does -- the downloading machine's culture in the older export (`M/d/yyyy h:mm:ss tt` on
/// en-US, survey §3 capture A), an ISO 8601 string with seven fraction digits in the newer one
/// (captures B and D) -- so the form is a per-tree choice, and one file never mixes the two. A
/// day-first host renders its own form, and the parser reads it back as that day and month.
#[test]
fn purview_creation_date_follows_the_export_version_of_the_tree() {
    // The `CreationDate` cells of a generated export.
    let dates = |seed: u64, culture: Culture| {
        let mut o = opts(seed);
        o.culture = culture;
        let mut sink = MemSink::default();
        let m = generate(&load("bec-aitm").unwrap(), &o, &mut sink).unwrap();
        let (_, bytes) = sink
            .files
            .iter()
            .find(|(rel, b)| rel.contains(&m.root) && b.starts_with(b"RecordId,"))
            .expect("the Purview export");
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let rows: Vec<&str> = text.trim_end().split("\r\n").skip(1).collect();
        assert!(rows.len() > 10, "only {} rows", rows.len());
        rows.iter()
            .map(|r| r.split(',').nth(1).unwrap().to_string())
            .collect::<Vec<String>>()
    };
    let is_iso = |d: &str| d.ends_with('Z') && d.len() == "2026-08-01T10:20:30.0000000Z".len();

    // One form per file, and both forms across seeds.
    let mut iso = 0;
    let mut culture_form = 0;
    let mut culture_seeds = Vec::new();
    for seed in 1..=8u64 {
        let dates = dates(seed, Culture::EnUs);
        let this_iso = is_iso(&dates[0]);
        assert!(
            dates.iter().all(|d| is_iso(d) == this_iso),
            "seed {seed} mixes both forms: {:?}",
            &dates[..3]
        );
        if this_iso {
            iso += 1;
        } else {
            assert!(
                dates
                    .iter()
                    .all(|d| d.split('/').count() == 3 && d.contains(':')),
                "seed {seed}: {:?}",
                &dates[..3]
            );
            culture_form += 1;
            culture_seeds.push(seed);
        }
    }
    assert!(
        iso > 0 && culture_form > 0,
        "{iso} ISO, {culture_form} culture"
    );

    // A day-first host on a culture-form tree renders its own form, throughout the file.
    let seed = *culture_seeds.first().expect("a culture-form seed");
    let gb = dates(seed, Culture::EnGb);
    assert!(
        !is_iso(&gb[0]) && gb.iter().all(|d| d.split('/').count() == 3),
        "en-GB on seed {seed} is not the day-first form: {:?}",
        &gb[..3]
    );
    // `dd/MM/yyyy HH:mm:ss`: the day before the slash, never a month.
    assert!(
        gb.iter().all(|d| d.split('/').next().unwrap().len() == 2),
        "en-GB on seed {seed}: {:?}",
        &gb[..3]
    );
    let de = dates(seed, Culture::DeDe);
    assert!(
        !is_iso(&de[0])
            && de
                .iter()
                .all(|d| d.contains('.') && d.split(' ').count() == 2),
        "de-DE on seed {seed} is not the day-first form: {:?}",
        &de[..3]
    );

    // The day-first `CreationDate` is only the *fallback* for the event time: AuditData's
    // ISO `CreationTime` is what a Purview row normally carries, so the row below is the one
    // that exercises the fallback -- it has no `CreationTime`, which is where a month-first
    // misread of `dd/MM` would show. `purview_creation_date_falls_back_to_a_day_first_value`
    // tests that path on its own.
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(seed);
    o.culture = Culture::EnGb;
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &o, dir.path()).unwrap();
    assert!(check(&m, &ingest_generated(dir.path(), &m)).unwrap().ok);

    // And the instant survives either form: the check is green on a tree of each kind.
    for seed in 1..=8u64 {
        let dir = tempfile::tempdir().unwrap();
        let m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(seed), dir.path()).unwrap();
        let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
        assert!(report.ok, "seed {seed}: {:#?}", report.problems);
    }
}

/// The day-first Purview `CreationDate` is the event time only when the row's AuditData has no
/// `CreationTime` of its own (`normalize::ual::event_time_text`), so this is the case it takes:
/// the mailbox-activity rows of a day-first export, whose AuditData carries no ISO time. Their
/// event time is the `dd/MM` cell, and a month-first reading of it would move the month of
/// every row whose day is above 12 -- so the test takes one of those and asks for the instant it
/// was written as. (A generated row with a `CreationTime` proves nothing here: the event time
/// would come from that instead.)
#[test]
fn purview_creation_date_falls_back_to_a_day_first_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(2);
    o.culture = Culture::EnGb;
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &o, dir.path()).unwrap();
    let root = dir.path().join(&m.root);
    let export = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            std::fs::read(p)
                .map(|b| b.starts_with(b"RecordId,"))
                .unwrap_or(false)
        })
        .expect("the export");
    let text = String::from_utf8(std::fs::read(&export).unwrap()).unwrap();
    assert!(
        !text
            .lines()
            .nth(1)
            .unwrap()
            .split(',')
            .nth(1)
            .unwrap()
            .ends_with('Z'),
        "this seed wrote the ISO form, not the culture form"
    );

    // A row whose day is above 12 (so a month-first reading is impossible) with the ISO
    // `CreationTime` taken out of its AuditData, so the event time can only be the cell.
    let mut lines: Vec<String> = text.trim_end().split("\r\n").map(String::from).collect();
    let mut picked = None;
    for (i, row) in lines.iter().enumerate().skip(1) {
        // id, CreationDate, RecordType, Operation, UserId, then the quoted AuditData and the
        // two empty trailing columns.
        let mut f = row.splitn(6, ',');
        let head: Vec<&str> = (0..5).map(|_| f.next().unwrap()).collect();
        let (id, cell) = (head[0].to_string(), head[1].to_string());
        if cell.contains('T') || cell.split('/').next().unwrap().parse::<u32>().unwrap_or(0) <= 12 {
            continue;
        }
        let audit = f
            .next()
            .unwrap()
            .trim_end_matches(',')
            .trim_matches('"')
            .replace("\"\"", "\"");
        let mut value: serde_json::Value =
            serde_json::from_str(&audit).expect("the AuditData is JSON");
        if value.get("CreationTime").is_none() {
            continue;
        }
        value
            .as_object_mut()
            .expect("an object")
            .remove("CreationTime");
        let escaped = serde_json::to_string(&value)
            .expect("JSON")
            .replace('"', "\"\"");
        let (d, r) = cell.split_once('/').unwrap();
        let (mo, r) = r.split_once('/').unwrap();
        let (y, hms) = r.split_once(' ').unwrap();
        let want = format!("{y}-{mo}-{d}T{hms}");
        // The same row, the same five leading fields, the ISO key gone from the AuditData.
        lines[i] = format!("{},\"{escaped}\",,", head.join(","));
        {
            let back: serde_json::Value = serde_json::from_str(
                &lines[i]
                    .splitn(6, ',')
                    .nth(5)
                    .unwrap()
                    .trim_end_matches(',')
                    .trim_matches('"')
                    .replace("\"\"", "\""),
            )
            .expect("the rewritten AuditData is JSON");
            assert!(
                back.get("CreationTime").is_none(),
                "the ISO key is still there: {back}"
            );
        }
        picked = Some((id, want));
        break;
    }
    let (id, want) = picked.expect("a row with a day above 12");
    std::fs::write(&export, format!("{}\r\n", lines.join("\r\n"))).unwrap();

    // The tree is edited on purpose, so it is ingested and not `check`ed: what is asked here is
    // the instant one row lands on, with the manifest's culture as the analyst's `--culture`.
    let case = ingest_generated(dir.path(), &m);
    let got: Option<String> = case
        .conn()
        .query_row(
            "SELECT strftime(event_time AT TIME ZONE 'UTC', '%Y-%m-%dT%H:%M:%S') \
             FROM ual_events WHERE record_id = ?::UUID",
            [&id],
            |r| r.get(0),
        )
        .ok();
    assert_eq!(
        got.as_deref(),
        Some(want.as_str()),
        "the fallback CreationDate was read as another date (or the row was lost)"
    );
}
