use chrono::{TimeZone, Utc};
use serde_json::json;
use sparrow_synth::options::{Culture, PsEdition};
use sparrow_synth::ps::*;

fn t(h: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 4, h, 5, 9).unwrap()
}

fn host(e: PsEdition, c: Culture) -> Host {
    Host::new(e, c, 120)
}

fn row(pairs: Vec<(&str, Val)>) -> Row {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

#[test]
fn culture_dates() {
    let us = host(PsEdition::Ps7, Culture::EnUs);
    assert_eq!(us.culture_date(t(14), DtKind::Utc), "9/4/2026 2:05:09 PM");
    assert_eq!(us.culture_date(t(0), DtKind::Utc), "9/4/2026 12:05:09 AM");
    assert_eq!(
        us.culture_date_short(t(14), DtKind::Utc),
        "9/4/2026 2:05 PM"
    );
    // Local kind: the host offset (+120 min) is applied.
    assert_eq!(us.culture_date(t(14), DtKind::Local), "9/4/2026 4:05:09 PM");
    assert_eq!(
        host(PsEdition::Ps7, Culture::EnGb).culture_date(t(14), DtKind::Utc),
        "04/09/2026 14:05:09"
    );
    assert_eq!(
        host(PsEdition::Ps7, Culture::DeDe).culture_date(t(14), DtKind::Utc),
        "04.09.2026 14:05:09"
    );
    assert_eq!(
        host(PsEdition::Ps7, Culture::JaJp).culture_date(t(4), DtKind::Utc),
        "2026/09/04 4:05:09"
    );
}

#[test]
fn dates_by_origin_and_edition() {
    let net = PsDate::dotnet(t(14), DtKind::Utc);
    let rest = PsDate::iso(t(14), 6);
    let p51 = host(PsEdition::Ps51, Culture::EnUs);
    let p7 = host(PsEdition::Ps7, Culture::EnUs);
    assert_eq!(p51.csv_date(&net), "9/4/2026 2:05:09 PM");
    assert_eq!(p51.json_date(&net), "/Date(1788530709000)/");
    assert_eq!(p7.json_date(&net), "2026-09-04T14:05:09Z");
    assert_eq!(
        p7.json_date(&PsDate::dotnet(t(14), DtKind::Local)),
        "2026-09-04T16:05:09+02:00"
    );
    assert_eq!(
        p7.json_date(&PsDate::dotnet(t(14), DtKind::Unspecified)),
        "2026-09-04T14:05:09"
    );
    // REST text: 5.1 keeps it, 7 re-renders it (culture in CSV, trimmed ISO Z in JSON).
    assert_eq!(p51.csv_date(&rest), "2026-09-04T14:05:09.000000Z");
    assert_eq!(p7.csv_date(&rest), "9/4/2026 2:05:09 PM");
    assert_eq!(p7.json_date(&rest), "2026-09-04T14:05:09Z");
}

#[test]
fn export_csv_quotes_nulls_by_edition_and_maps_later_rows_by_name() {
    let rows = vec![
        row(vec![
            ("A", Val::Str("x\"y".into())),
            ("B", Val::Null),
            ("C", Val::Bool(true)),
        ]),
        row(vec![
            ("C", Val::Int(5)),
            ("A", Val::Str("".into())),
            ("Z", Val::Str("dropped".into())),
        ]),
    ];
    let mut ev = DateEvidence::default();
    let p7 = export_csv(&host(PsEdition::Ps7, Culture::EnUs), &rows, &mut ev);
    assert_eq!(
        p7.text,
        "\"A\",\"B\",\"C\"\r\n\"x\"\"y\",,\"True\"\r\n\"\",,\"5\"\r\n"
    );
    assert_eq!(p7.spans, vec![(2, 2), (3, 3)]);
    assert_eq!(
        export_csv(&host(PsEdition::Ps51, Culture::EnUs), &rows, &mut ev).text,
        "\"A\",\"B\",\"C\"\r\n\"x\"\"y\",\"\",\"True\"\r\n\"\",\"\",\"5\"\r\n"
    );
    assert_eq!(
        export_csv(&host(PsEdition::Ps7, Culture::EnUs), &[], &mut ev).text,
        ""
    );
    // A multi-line cell makes its row span two physical lines.
    let multi = vec![
        row(vec![("D", Val::Str("If the message:\r\n\tx".into()))]),
        row(vec![("D", Val::Str("y".into()))]),
    ];
    assert_eq!(
        export_csv(&host(PsEdition::Ps7, Culture::EnUs), &multi, &mut ev).spans,
        vec![(2, 3), (4, 4)]
    );
}

#[test]
fn date_evidence_counts_decisive_days() {
    let gb = host(PsEdition::Ps7, Culture::EnGb);
    let mut ev = DateEvidence::default();
    let d = |day| {
        Val::Date(PsDate::dotnet(
            Utc.with_ymd_and_hms(2026, 9, day, 1, 0, 0).unwrap(),
            DtKind::Utc,
        ))
    };
    export_csv(
        &gb,
        &[row(vec![("T", d(4))]), row(vec![("T", d(11))])],
        &mut ev,
    );
    assert!(ev.all_ambiguous());
    // DateText renders the same but is not evidence.
    let mut none = DateEvidence::default();
    export_csv(
        &gb,
        &[row(vec![(
            "T",
            Val::DateText(PsDate::dotnet(
                Utc.with_ymd_and_hms(2026, 9, 20, 1, 0, 0).unwrap(),
                DtKind::Utc,
            )),
        )])],
        &mut none,
    );
    assert_eq!(none.culture_dates, 0);
    export_csv(&gb, &[row(vec![("T", d(13))])], &mut ev);
    assert_eq!((ev.culture_dates, ev.decisive), (3, 1));
    assert!(!ev.all_ambiguous());
    let mut ja = DateEvidence::default();
    export_csv(
        &host(PsEdition::Ps7, Culture::JaJp),
        &[row(vec![("T", d(4))])],
        &mut ja,
    );
    assert_eq!(ja.culture_dates, 0);
    // 9/9 reads the same in either order: no evidence at all.
    let mut same = DateEvidence::default();
    export_csv(&gb, &[row(vec![("T", d(9))])], &mut same);
    assert_eq!(same.culture_dates, 0);
}

#[test]
fn convert_to_json_styles() {
    let one = vec![row(vec![
        ("a", Val::Int(1)),
        ("s", Val::Str("<b>&'".into())),
    ])];
    let p7 = host(PsEdition::Ps7, Culture::EnUs);
    let p51 = host(PsEdition::Ps51, Culture::EnUs);
    let r = convert_to_json(&p7, &one, false);
    assert_eq!(r.text, "{\r\n  \"a\": 1,\r\n  \"s\": \"<b>&'\"\r\n}");
    assert_eq!(r.spans, vec![(1, 4)]);
    assert_eq!(
        convert_to_json(&p51, &one, false).text,
        "{\r\n    \"a\":  1,\r\n    \"s\":  \"\\u003cb\\u003e\\u0026\\u0027\"\r\n}"
    );
    let two = vec![one[0].clone(), one[0].clone()];
    let arr = convert_to_json(&p7, &two, false);
    assert!(arr.text.starts_with("[\r\n  {\r\n    \"a\": 1,"));
    assert_eq!(arr.spans, vec![(2, 5), (6, 9)]);
    assert_eq!(
        convert_to_json(&p7, &one, true).text,
        "{\"a\":1,\"s\":\"<b>&'\"}"
    );
    assert_eq!(convert_to_json(&p7, &[], false).text, "");
    assert_eq!(json_text(&p7, &json!([]), false), "[]");
    assert_eq!(
        json_text(&p51, &json!({"x": []}), false),
        "{\r\n    \"x\":  [\r\n\r\n    ]\r\n}"
    );
}

#[test]
fn format_list_pads_names_and_wraps_on_51() {
    let blocks = vec![row(vec![
        ("Name", Val::Str("Inbox".into())),
        ("ItemsInFolder", Val::Int(3)),
    ])];
    let mut ev = DateEvidence::default();
    let fl = format_list(&host(PsEdition::Ps7, Culture::EnUs), &blocks, &mut ev);
    assert_eq!(
        fl.text,
        "\r\n\r\nName          : Inbox\r\nItemsInFolder : 3\r\n\r\n\r\n\r\n"
    );
    assert_eq!(fl.spans, vec![(3, 4)]);
    let long = vec![row(vec![("K", Val::Str("x".repeat(130)))])];
    let wrapped = format_list(&host(PsEdition::Ps51, Culture::EnUs), &long, &mut ev).text;
    let lines: Vec<&str> = wrapped.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "{wrapped}");
    assert!(lines[1].starts_with("    "));
}

#[test]
fn format_list_two_blocks_span_independently() {
    let blocks = vec![
        row(vec![
            ("Name", Val::Str("Inbox".into())),
            ("ItemsInFolder", Val::Int(3)),
        ]),
        row(vec![("Name", Val::Str("Drafts".into()))]),
    ];
    let mut ev = DateEvidence::default();
    let fl = format_list(&host(PsEdition::Ps7, Culture::EnUs), &blocks, &mut ev);
    assert_eq!(
        fl.text,
        "\r\n\r\nName          : Inbox\r\nItemsInFolder : 3\r\n\r\nName : Drafts\r\n\r\n\r\n\r\n"
    );
    // The second block's own (shorter) name padding is independent of the first's, and its
    // span starts after the first block's own trailing blank line.
    assert_eq!(fl.spans, vec![(3, 4), (6, 6)]);
}

#[test]
fn encodings() {
    assert_eq!(Encoding::Utf8Bom.encode("a"), vec![0xEF, 0xBB, 0xBF, b'a']);
    assert_eq!(Encoding::Utf16LeBom.encode("a"), vec![0xFF, 0xFE, b'a', 0]);
    assert_eq!(Encoding::Utf16LeNoBom.encode("a"), vec![b'a', 0]);
    assert_eq!(Encoding::Ascii.encode("é"), vec![b'?']);
    assert_eq!(Encoding::Cp1252.encode("é"), vec![0xE9]);
    assert_eq!(
        Encoding::export_csv_utf8(PsEdition::Ps51),
        Encoding::Utf8Bom
    );
    assert_eq!(
        Encoding::out_file_default(PsEdition::Ps51),
        Encoding::Utf16LeBom
    );
    assert_eq!(Encoding::out_file_default(PsEdition::Ps7), Encoding::Utf8);
}
