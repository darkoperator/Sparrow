use sparrow_synth::check::check;
use sparrow_synth::generate::{generate, generate_to_dir, generate_zip};
use sparrow_synth::options::{Collector, Culture, GenerateOptions, SigninExport};
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
    // Message trace summary: Windows-1252 (the real download's encoding), quoted header, CRLF.
    let (_, mt) = file("MTSummary_Message trace report - _2026-09-10T141500.000Z__");
    assert_eq!(&mt[..4], b"\"ori", "{:?}", &mt[..4]);
    let text = sparrow_core::readers::text::decode(&mt).text;
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

/// Task F9.2: the Exchange message-trace "summary report" download is a Windows-1252 file (the
/// real capture reads as that encoding), and a subject with a non-ASCII character exercises the
/// encoding end to end: the byte is one, the parser decodes it back to the character, and the
/// stored text is neither mangled nor a replacement character.
#[test]
fn message_trace_summary_is_windows_1252_and_decodes_back() {
    let mut sink = MemSink::default();
    let m = generate(&load("bec-aitm").unwrap(), &opts(2), &mut sink).unwrap();
    let (rel, bytes) = sink
        .files
        .iter()
        .find(|(rel, _)| rel.contains("MTSummary_"))
        .expect("the message-trace summary");
    assert!(rel.starts_with(&m.root));
    let decoded = sparrow_core::readers::text::decode(bytes);
    assert_eq!(
        decoded.encoding,
        sparrow_core::readers::text::TextEncoding::Windows1252,
        "{rel}"
    );
    assert!(
        decoded
            .text
            .starts_with("\"origin_timestamp_utc\",\"sender_address\",\"recipient_status\"")
    );
    // The non-ASCII character is a single 0xE9 byte, not its two-byte UTF-8 spelling.
    assert!(
        bytes.contains(&0xE9) && !bytes.windows(2).any(|w| w == [0xC3, 0xA9]),
        "no Windows-1252 subject byte in {rel}"
    );
    assert!(
        decoded.text.contains('é'),
        "no non-ASCII subject to exercise the encoding"
    );

    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(2), dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &m);
    let q = |sql: &str| {
        case.conn()
            .query_row(sql, [], |r| r.get::<_, i64>(0))
            .unwrap()
    };
    assert!(
        q("SELECT count(*) FROM message_trace WHERE subject LIKE '%é%'") > 0,
        "the subject did not survive the encoding"
    );
    assert_eq!(
        q("SELECT count(*) FROM message_trace WHERE subject LIKE '%Caf?%'"),
        0,
        "the non-ASCII subject was mangled"
    );
    assert_eq!(
        q("SELECT count(*) FROM message_trace WHERE position('\u{fffd}' in subject) > 0"),
        0,
        "a subject holds a replacement character"
    );
}

/// Task F9.3: the Purview audit search export renders `CreationDate` the way its own version
/// does -- the downloading machine's culture in the older export (`M/d/yyyy h:mm:ss tt` on
/// en-US, survey §3 capture A), an ISO 8601 string with seven fraction digits in the newer one
/// (captures B and D) -- so the form is a per-tree choice, and one file never mixes the two.
#[test]
fn purview_creation_date_follows_the_export_version_of_the_tree() {
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
        let field = |row: &str| row.split(',').nth(1).unwrap().to_string();
        rows.iter().map(|r| field(r)).collect::<Vec<String>>()
    };

    // One form per file, whichever the tree's export version writes, and both forms across
    // seeds.
    let mut iso = 0;
    let mut culture_form = 0;
    for seed in 1..=8u64 {
        let dates = dates(seed, Culture::EnUs);
        let is_iso =
            dates[0].ends_with('Z') && dates[0].len() == "2026-08-01T10:20:30.0000000Z".len();
        assert!(
            dates.iter().all(|d| d.ends_with('Z') == is_iso),
            "seed {seed} mixes both forms: {:?}",
            &dates[..3]
        );
        if is_iso {
            iso += 1;
        } else {
            // `M/d/yyyy h:mm:ss tt`, the capture-A rendering.
            assert!(
                dates[0].split('/').count() == 3 && dates[0].contains(":"),
                "seed {seed}: {}",
                dates[0]
            );
            culture_form += 1;
        }
    }
    assert!(
        iso > 0 && culture_form > 0,
        "{iso} ISO, {culture_form} culture"
    );

    // A day-first host on a culture-form tree renders its own form, and the file is still one
    // form throughout.
    let gb = dates(1, Culture::EnGb);
    if !gb[0].ends_with('Z') {
        assert!(
            gb.iter()
                .all(|d| d.split('/').count() == 3 && d.split('/').next().unwrap().len() == 2),
            "en-GB: {:?}",
            &gb[..3]
        );
    }
    let de = dates(1, Culture::DeDe);
    if !de[0].ends_with('Z') {
        assert!(
            de.iter()
                .all(|d| d.contains('.') && d.split(' ').count() == 2),
            "de-DE: {:?}",
            &de[..3]
        );
    }

    // The instant survives either form: the case loads the record times the manifest records,
    // so the check is green on a tree of each form.
    for seed in 1..=8u64 {
        let dir = tempfile::tempdir().unwrap();
        let m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(seed), dir.path()).unwrap();
        let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
        assert!(report.ok, "seed {seed}: {:#?}", report.problems);
    }
}
