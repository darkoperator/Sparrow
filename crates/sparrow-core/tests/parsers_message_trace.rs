use serde_json::json;
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use std::path::{Path, PathBuf};

const ALICE: &str = "alice@contoso.example";
const TRACE: &str = "0e0e0e0e-0000-4000-8000-000000000003";
const SUMMARY: &str = "MTSummary_Message trace report - _2026-09-10T141500.000Z__7c9e6679-7425-40de-944b-e07fc1f90ae7.csv";

fn capture(base: &Path) -> PathBuf {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    root
}

fn ingest(base: &Path) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        base,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    (case, report)
}

fn row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("no report row for {rel}"))
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn hawk_trace(id: Option<&str>, recipient: &str) -> serde_json::Value {
    json!({
        "Organization": "contoso.onmicrosoft.com", "MessageId": "<m3@contoso.example>",
        "Received": "2026-09-01T10:20:00.1234567", "SenderAddress": "Alice@contoso.example",
        "RecipientAddress": recipient, "Subject": "Updated bank details", "Status": "Delivered",
        "ToIP": null, "FromIP": "203.0.113.10", "Size": 2048, "MessageTraceId": id,
        "StartDate": "2026-08-01T00:00:00.0000000Z", "EndDate": "2026-09-10T00:00:00.0000000Z",
        "Index": 0
    })
}

const SUMMARY_HEADER: &[&str] = &[
    "origin_timestamp_utc",
    "sender_address",
    "recipient_status",
    "message_subject",
    "total_bytes",
    "message_id",
    "network_message_id",
    "original_client_ip",
    "directionality",
    "connector_id",
    "delivery_priority",
];

fn summary_row(recipients: &str) -> String {
    csv_line(&[
        "2026-09-01T10:20:00.0000000Z",
        ALICE,
        recipients,
        "Updated bank details",
        "2048",
        "<m3@contoso.example>",
        TRACE,
        "203.0.113.10",
        "Originating",
        "",
        "Normal",
    ])
}

#[test]
fn hawk_message_trace_loads_one_row_per_recipient_record() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &rel,
        fixtures::ps_json(&json!([
            hawk_trace(Some(&TRACE.to_uppercase()), "X@fabrikam.example"),
            hawk_trace(Some(&TRACE.to_uppercase()), "y@fabrikam.example")
        ]))
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(row(&report, &rel).records_loaded, 2);
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT sender || '|' || recipient || '|' || subject || '|' || status || '|' || from_ip || '|' ||
                        size_bytes || '|' || internet_message_id || '|' || organization || '|' || time_tz_assumed
                 FROM message_trace WHERE record_key = '{TRACE}|x@fabrikam.example'"
            )
        ),
        "alice@contoso.example|x@fabrikam.example|Updated bank details|Delivered|203.0.113.10|2048|<m3@contoso.example>|contoso.onmicrosoft.com|true"
    );
    assert_eq!(
        count(
            &case,
            "SELECT min(epoch(received)::BIGINT) FROM message_trace"
        ),
        1788258000
    );
}

#[test]
fn portal_and_hawk_copies_of_a_message_are_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let hawk = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &hawk,
        fixtures::ps_json(&json!([hawk_trace(Some(TRACE), "x@fabrikam.example")])).as_bytes(),
    );
    let portal = format!("{ALICE}/{SUMMARY}");
    let text_csv = csv_line(SUMMARY_HEADER) + &summary_row("x@fabrikam.example##Delivered");
    fixtures::write(&root, &portal, &fixtures::utf16le_no_bom(&text_csv));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        row(&report, &portal).artifact_id.as_deref(),
        Some("portal.message_trace")
    );
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 1);
    assert_eq!(
        text(
            &case,
            "SELECT direction || '|' || organization FROM message_trace"
        ),
        "Originating|contoso.onmicrosoft.com"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'message_trace'"
        ),
        2
    );
}

#[test]
fn portal_summary_rows_split_per_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    let csv = csv_line(SUMMARY_HEADER)
        + &summary_row("a@fabrikam.example##Delivered;b@fabrikam.example##Failed");
    fixtures::write(&root, SUMMARY, &fixtures::utf16le_no_bom(&csv));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let f = row(&report, SUMMARY);
    assert_eq!((f.records_read, f.records_loaded), (2, 2));
    assert_eq!(
        text(
            &case,
            "SELECT string_agg(recipient || ':' || status, ',' ORDER BY recipient) FROM message_trace"
        ),
        "a@fabrikam.example:Delivered,b@fabrikam.example:Failed"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(DISTINCT line_start) FROM record_sources WHERE table_name = 'message_trace'"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT epoch(received)::BIGINT FROM message_trace LIMIT 1"
        ),
        1788258000
    );
}

#[test]
fn windows_1252_summary_loads_with_a_lossy_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    let mut bytes = SUMMARY_HEADER.join(",").into_bytes();
    bytes.extend_from_slice(b"\r\n2026-09-01T10:20:00.0000000Z,alice@contoso.example,x@fabrikam.example##Delivered,Factur");
    bytes.push(0xE9);
    bytes.extend_from_slice(
        format!(",2048,<m3@contoso.example>,{TRACE},203.0.113.10,Originating,,Normal\r\n")
            .as_bytes(),
    );
    fixtures::write(&root, SUMMARY, &bytes);
    let (case, report) = ingest(dir.path());
    let f = row(&report, SUMMARY);
    assert_eq!(
        (f.status, f.records_loaded),
        (FileStatus::Parsed, 1),
        "{f:#?}"
    );
    assert!(
        f.warnings.iter().any(|w| w.contains("lossy")),
        "{:?}",
        f.warnings
    );
    assert_eq!(text(&case, "SELECT subject FROM message_trace"), "Facturé");
}

#[test]
fn trace_without_an_id_is_a_parse_error_and_other_shapes_are_not_supported() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &rel,
        fixtures::ps_json(&json!([
            hawk_trace(Some(TRACE), "x@fabrikam.example"),
            hawk_trace(None, "y@fabrikam.example")
        ]))
        .as_bytes(),
    );
    let (_case, report) = ingest(dir.path());
    let f = row(&report, &rel);
    assert_eq!((f.records_loaded, f.records_error), (1, 1));

    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, &rel, br#"[{"Foo": 1}]"#);
    let (_case, report) = ingest(dir.path());
    assert_eq!(row(&report, &rel).status, FileStatus::NotSupported);
}

/// Every base table as (name, rows, content hash), without the random case id and the clock columns.
fn all_tables(case: &Case) -> Vec<(String, i64, String)> {
    let sql: String = case
        .conn()
        .query_row(
            "WITH c AS (
                SELECT table_name,
                       string_agg(format('\"{}\"', column_name), ',' ORDER BY ordinal_position) AS cols
                FROM information_schema.columns
                WHERE table_schema = 'main' AND table_name <> 'case_meta'
                  AND table_name IN (SELECT table_name FROM information_schema.tables
                                     WHERE table_type = 'BASE TABLE' AND table_schema = 'main')
                  AND NOT regexp_matches(column_name, '(_at|started|finished|duration|elapsed)$')
                GROUP BY table_name)
             SELECT string_agg(format('SELECT ''{}'' AS t, count(*) AS n, CAST(coalesce(sum(hash({})), 0) AS VARCHAR) AS h FROM \"{}\"',
                                      table_name, cols, table_name), ' UNION ALL ' ORDER BY table_name)
             FROM c",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut stmt = case.conn().prepare(&format!("{sql} ORDER BY t")).unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// The tables and each file's report line (status, read, loaded, duplicate, error, warnings) of an ingest of
/// `base` with `batch_rows = batch`.
fn run_batched(base: &Path, batch: usize) -> (Vec<(String, i64, String)>, Vec<String>) {
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions {
        batch_rows: batch,
        ..IngestOptions::default()
    };
    let report = ingest_path(&mut case, base, &ParserRegistry::builtin(), &opts).unwrap();
    let files = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .map(|f| {
            format!(
                "{} {:?} {} {} {} {} {:?}",
                f.rel_path,
                f.status,
                f.records_read,
                f.records_loaded,
                f.records_duplicate,
                f.records_error,
                f.warnings
            )
        })
        .collect();
    (all_tables(&case), files)
}

fn trace_at(id: Option<&str>, recipient: &str, received: &str, subject: &str) -> serde_json::Value {
    let mut t = hawk_trace(id, recipient);
    t["Received"] = json!(received);
    t["Subject"] = json!(subject);
    t
}

fn summary_line(id: &str, recipients: &str, time: &str, subject: &str) -> String {
    csv_line(&[
        time,
        ALICE,
        recipients,
        subject,
        "2048",
        "<m9@contoso.example>",
        id,
        "203.0.113.10",
        "Originating",
        "",
        "Normal",
    ])
}

#[test]
fn every_batch_size_stores_what_one_batch_stores() {
    // Message trace files are streamed and staged in batches: a later copy of a key in the same file stays a
    // duplicate across batches (the file's first copy wins), rejects and bad times stay errors, and a summary
    // line's recipients are all its rows, whatever the batch size.
    let (t1, t2, t3, t4) = (
        "0e0e0e0e-0000-4000-8000-0000000000a1",
        "0e0e0e0e-0000-4000-8000-0000000000a2",
        "0e0e0e0e-0000-4000-8000-0000000000a3",
        "0e0e0e0e-0000-4000-8000-0000000000a4",
    );
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let hawk = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &hawk,
        fixtures::ps_json(&json!([
            trace_at(Some(t1), "x@fabrikam.example", "2026-09-01T10:20:00", "one"),
            trace_at(Some(t2), "y@fabrikam.example", "2026-09-01T10:21:00", "two"),
            trace_at(
                Some(t1),
                "X@fabrikam.example",
                "2026-09-01T10:22:00",
                "one again"
            ),
            trace_at(None, "z@fabrikam.example", "2026-09-01T10:23:00", "no id"),
            trace_at(Some(t3), "z@fabrikam.example", "not a time", "bad time"),
            trace_at(
                Some(t2),
                "y@fabrikam.example",
                "2026-09-01T10:24:00",
                "two again"
            ),
            trace_at(
                Some(t4),
                "w@fabrikam.example",
                "2026-09-01T10:25:00",
                "four"
            ),
        ]))
        .as_bytes(),
    );
    let portal = format!("{ALICE}/{SUMMARY}");
    let at = "2026-09-01T11:00:00.0000000Z";
    let csv = csv_line(SUMMARY_HEADER)
        + &summary_line(
            t1,
            "x@fabrikam.example##Delivered;b@fabrikam.example##Failed",
            at,
            "s1",
        )
        + &summary_line(t3, "c@fabrikam.example##Delivered", at, "s2")
        + &summary_line(t1, "b@fabrikam.example##Delivered", at, "s1 again")
        + &summary_line("", "d@fabrikam.example##Delivered", at, "no id")
        + &summary_line(
            t4,
            "e@fabrikam.example##Delivered",
            "not a time",
            "bad time",
        )
        + &summary_line(
            t3,
            "c@fabrikam.example##Delivered;f@fabrikam.example##Pending",
            at,
            "s2 again",
        )
        + &summary_line(t2, "", at, "no recipients");
    fixtures::write(&root, &portal, &fixtures::utf16le_no_bom(&csv));
    let (want_tables, want_files) = run_batched(dir.path(), usize::MAX);
    let file = |rel: &str| {
        want_files
            .iter()
            .find(|f| f.starts_with(rel))
            .unwrap()
            .clone()
    };
    // read / loaded / duplicate / error. Hawk: 7 records; t1|x, t2|y and t4|w kept, 2 later copies, no id and a
    // bad time.
    assert!(file(&hawk).contains(" Parsed 7 3 2 2 "), "{}", file(&hawk));
    // Summary: 7 lines giving 9 (the line without an id counts once, the one without a recipient is a row keyed
    // `<id>|`); t1|x fills the Hawk row, t1|b, t3|c, t3|f and t2| are new, two later copies, the bad time and the
    // missing id are errors.
    assert!(
        file(&portal).contains(" Parsed 9 5 2 2 "),
        "{}",
        file(&portal)
    );
    for batch in [1, 2, 3] {
        let (tables, files) = run_batched(dir.path(), batch);
        assert_eq!(files, want_files, "batch {batch}: file reports");
        assert_eq!(tables, want_tables, "batch {batch}: tables");
    }
}

#[test]
fn a_later_get_messagetrace_record_makes_the_file_get_messagetrace() {
    // The shape is Get-MessageTrace when ANY record has MessageTraceId + RecipientAddress, even after a record of
    // the summary shape: that first record is then a record without a MessageTraceId.
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &rel,
        fixtures::ps_json(&json!([
            {"origin_timestamp_utc": "2026-09-01T10:20:00Z", "network_message_id": TRACE,
             "recipient_status": "x@fabrikam.example##Delivered", "sender_address": ALICE},
            hawk_trace(Some(TRACE), "y@fabrikam.example"),
        ]))
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, &rel);
    assert_eq!(
        (f.status, f.records_read, f.records_loaded, f.records_error),
        (FileStatus::Parsed, 2, 1, 1),
        "{f:#?}"
    );
    assert_eq!(
        text(&case, "SELECT record_key FROM message_trace"),
        format!("{TRACE}|y@fabrikam.example")
    );
    assert_eq!(
        text(&case, "SELECT error FROM parse_errors"),
        "message trace record has no MessageTraceId"
    );
}

/// Thirteen keys, so the error names only the first record's first twelve.
fn foreign_record(tag: &str) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for k in [
        "Zulu", "Alpha", "Mike", "Bravo", "Yankee", "Charlie", "Xray", "Delta", "Whiskey", "Echo",
        "Victor", "Foxtrot", "Uniform",
    ] {
        m.insert(format!("{k}{tag}"), json!(1));
    }
    serde_json::Value::Object(m)
}

#[test]
fn an_unsupported_shape_names_the_first_record_s_first_twelve_columns() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(
        &root,
        &rel,
        fixtures::ps_json(&json!([foreign_record("1"), foreign_record("2")])).as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    let f = row(&report, &rel);
    // The values the collected parser (aed066fc) gave.
    assert_eq!(
        (f.status, f.records_read, f.records_loaded, f.records_error),
        (FileStatus::NotSupported, 0, 0, 0)
    );
    assert_eq!(
        f.warnings,
        [
            "hawk.user.message_trace: no message trace fields (MessageTraceId + RecipientAddress, or network_message_id + recipient_status) in [Zulu1, Alpha1, Mike1, Bravo1, Yankee1, Charlie1, Xray1, Delta1, Whiskey1, Echo1, Victor1, Foxtrot1]"
        ]
    );
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 0);
}

#[test]
fn a_file_of_only_unreadable_records_records_them_and_loads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rel = format!("{ALICE}/Message_Trace_{ALICE}.json");
    fixtures::write(&root, &rel, b"[1, \"two\", [3]]");
    let (case, report) = ingest(dir.path());
    let f = row(&report, &rel);
    // The values the collected parser (aed066fc) gave.
    assert_eq!(
        (
            f.status,
            f.records_read,
            f.records_loaded,
            f.records_duplicate,
            f.records_error
        ),
        (FileStatus::Parsed, 3, 0, 0, 3)
    );
    assert!(f.warnings.is_empty(), "{:?}", f.warnings);
    let errs: String = text(
        &case,
        "SELECT string_agg(record_ordinal || ':' || line_start || ':' || byte_offset || ':' || byte_length || ':' || error || ':' || raw_snippet, ' | ' ORDER BY record_ordinal) FROM parse_errors",
    );
    assert_eq!(
        errs,
        "0:1:1:1:record is not a JSON object:1 | 1:1:4:5:record is not a JSON object:\"two\" | 2:1:11:3:record is not a JSON object:[3]"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 0);
}
