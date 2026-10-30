//! The Exchange admin center message trace DETAIL ("extended") report: classification, the
//! lossless `message_trace_events` table, and its collapse into `message_trace` (one row per
//! message and recipient).

use chrono::{TimeZone, Utc};
use sparrow_core::Case;
use sparrow_core::discovery::Tool::{Hawk, Invictus, PortalExport};
use sparrow_core::discovery::registry::Registry;
use sparrow_core::fixtures::{self, csv_line, utf8_bom, utf16le_bom, utf16le_no_bom};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::profile::availability::compute;
use sparrow_core::profile::{ProfileOptions, refresh};
use sparrow_core::verify::verify_record;
use std::path::Path;

const DETAIL_REL: &str = "MTDetail_Message trace report - _2026-08-04T000000.000Z__6b5a8a0e-7a1e-4f6c-9d6f-2f0f6a1c1d11.csv";
const SUMMARY_REL: &str = "MTSummary_Message trace report - _2026-08-04T000000.000Z__7c9e6679-7425-40de-944b-e07fc1f90ae7.csv";
const NMID: &str = "AAAAAAAA-0000-4000-8000-000000000001";
const NMID_LOWER: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const SUBJECT: &str = "Wire details, urgent\r\nplease read";

/// The report's 27 columns, in Microsoft's order.
const COLUMNS: [&str; 27] = [
    "date_time_utc",
    "client_ip",
    "client_hostname",
    "server_ip",
    "server_hostname",
    "source_context",
    "connector_id",
    "source",
    "event_id",
    "internal_message_id",
    "message_id",
    "network_message_id",
    "recipient_address",
    "recipient_status",
    "total_bytes",
    "recipient_count",
    "related_recipient_address",
    "reference",
    "message_subject",
    "sender_address",
    "return_path",
    "message_info",
    "directionality",
    "tenant_id",
    "original_client_ip",
    "original_server_ip",
    "custom_data",
];

type Ev = Vec<(&'static str, String)>;

fn ev(pairs: &[(&'static str, &str)]) -> Ev {
    pairs.iter().map(|(k, v)| (*k, v.to_string())).collect()
}

/// A detail report as text: every field quoted, CRLF. `reverse` writes the columns backwards.
fn report_text(events: &[Ev], reverse: bool) -> String {
    let mut cols: Vec<&str> = COLUMNS.to_vec();
    if reverse {
        cols.reverse();
    }
    let mut out = csv_line(&cols);
    for e in events {
        let fields: Vec<&str> = cols
            .iter()
            .map(|c| {
                e.iter()
                    .find(|(k, _)| k == c)
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("")
            })
            .collect();
        out += &csv_line(&fields);
    }
    out
}

fn report(events: &[Ev]) -> Vec<u8> {
    utf16le_no_bom(&report_text(events, false))
}

// ---- the main message ----

fn e_receive() -> Ev {
    ev(&[
        ("date_time_utc", "2026-08-04T17:53:09.6290000Z"),
        ("client_ip", "2001:DB8::10"),
        ("client_hostname", "mail-ch2.contoso.example"),
        ("server_ip", "fe80::1%3"),
        ("server_hostname", "srv1.contoso.example"),
        ("connector_id", "Default frontend"),
        ("source", "SMTP"),
        ("event_id", "RECEIVE"),
        ("internal_message_id", "1234567890"),
        ("message_id", "<m1@contoso.example>"),
        ("network_message_id", NMID),
        (
            "recipient_address",
            "Bob@Contoso.example;carol@contoso.example",
        ),
        ("recipient_status", "250 2.1.5 Recipient OK"),
        ("total_bytes", "2048"),
        ("recipient_count", "2"),
        ("reference", "ref-1"),
        ("message_subject", SUBJECT),
        ("sender_address", "Alice@Contoso.example"),
        ("return_path", "alice@contoso.example"),
        ("message_info", "S:Foo=Bar;S:Baz=Qux"),
        ("directionality", "Originating"),
        ("tenant_id", "bbbbbbbb-0000-4000-8000-000000000002"),
        ("original_client_ip", "fe80::5%2"),
        ("original_server_ip", "198.51.100.1"),
        ("custom_data", "S:Cd=1;S:Ce=2"),
    ])
}

fn e_expand() -> Ev {
    ev(&[
        ("date_time_utc", "2026-08-04T17:53:09.7000000Z"),
        ("source", "RESOLVER"),
        ("event_id", "EXPAND"),
        ("message_id", "<m1@contoso.example>"),
        ("network_message_id", NMID),
        ("recipient_address", "bob@contoso.example"),
        ("related_recipient_address", "Group@contoso.example"),
        ("total_bytes", "2100"),
        ("sender_address", "relay@contoso.example"),
        ("directionality", "Undefined"),
        ("connector_id", "Other connector"),
        ("original_client_ip", "203.0.113.50"),
    ])
}

fn e_deliver(at: &str, recipient: &str, ip: &str) -> Ev {
    ev(&[
        ("date_time_utc", at),
        ("source", "STOREDRIVER"),
        ("event_id", "DELIVER"),
        ("message_id", "<m1@contoso.example>"),
        ("network_message_id", NMID),
        ("recipient_address", recipient),
        ("total_bytes", "1900"),
        ("original_client_ip", ip),
    ])
}

fn e_dup_redirect() -> Ev {
    ev(&[
        ("date_time_utc", "2026-08-04T17:53:10.3000000Z"),
        ("source", "ROUTING"),
        ("source_context", "Forwarding SMTP Address"),
        ("event_id", "DUPLICATEREDIRECT"),
        ("message_id", "<m1@contoso.example>"),
        ("network_message_id", NMID),
        ("recipient_address", "bob@contoso.example"),
        ("related_recipient_address", "Dave@Fabrikam.example"),
    ])
}

fn e_agentinfo() -> Ev {
    ev(&[
        ("date_time_utc", "2026-08-04T17:53:11.0000000Z"),
        ("source", "AGENT"),
        ("event_id", "AGENTINFO"),
        ("network_message_id", NMID),
        ("recipient_address", "carol@contoso.example"),
    ])
}

/// Six events of one message; the file order is not the time order.
fn main_message() -> Vec<Ev> {
    vec![
        e_expand(),
        e_receive(),
        e_dup_redirect(),
        e_deliver(
            "2026-08-04T17:53:10.1000000Z",
            "bob@contoso.example",
            "198.51.100.77",
        ),
        e_deliver("2026-08-04T17:53:10.2000000Z", "carol@contoso.example", ""),
        e_agentinfo(),
    ]
}

// ---- harness ----

fn ingest_into(case: &mut Case, base: &Path) -> IngestReport {
    ingest_path(
        case,
        base,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap()
}

fn ingest(base: &Path) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let report = ingest_into(&mut case, base);
    (case, report)
}

/// A case holding one detail report in a bare folder.
fn case_of(bytes: &[u8]) -> (Case, IngestReport) {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(&dir.path().join("downloads"), DETAIL_REL, bytes);
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
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

fn epoch_us(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32, micros: i64) -> i64 {
    Utc.with_ymd_and_hms(y, mo, d, h, mi, s)
        .unwrap()
        .timestamp()
        * 1_000_000
        + micros
}

fn artifact(tool: sparrow_core::discovery::Tool, head: &[u8]) -> Option<&'static str> {
    Registry::builtin()
        .classify_with_head(tool, "export.csv", Some(head))
        .map(|c| c.artifact_id)
}

/// Every (status) of the `message_trace` rows, `recipient=status`, ordered.
fn statuses(case: &Case) -> String {
    text(
        case,
        "SELECT string_agg(recipient || '=' || coalesce(status, 'NULL'), ',' ORDER BY recipient)
         FROM message_trace",
    )
}

// ---- classification ----

#[test]
fn detail_header_is_recognised_whatever_the_encoding_name_or_tool() {
    let text = report_text(&[e_receive()], false);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("utf-16le without bom", utf16le_no_bom(&text)),
        ("utf-16le with bom", utf16le_bom(&text)),
        ("utf-8", text.as_bytes().to_vec()),
        ("utf-8 with bom", utf8_bom(&text)),
    ];
    for (what, head) in &cases {
        for tool in [PortalExport, Hawk, Invictus] {
            let c = Registry::builtin()
                .classify_with_head(tool, "export.csv", Some(head))
                .unwrap_or_else(|| panic!("{what} {tool:?}: not classified"));
            assert_eq!(
                (c.artifact_id, c.target),
                ("portal.message_trace_detail", "message_trace_events"),
                "{what} {tool:?}"
            );
        }
    }
    // The header alone (no rows), and the columns in another order.
    assert_eq!(
        artifact(PortalExport, &report(&[])),
        Some("portal.message_trace_detail")
    );
    assert_eq!(
        artifact(
            PortalExport,
            &utf16le_no_bom(&report_text(&[e_receive()], true))
        ),
        Some("portal.message_trace_detail")
    );
}

#[test]
fn bomless_utf16_file_in_a_bare_folder_is_the_detail_report() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("downloads");
    fixtures::write(&folder, DETAIL_REL, &report(&main_message()));
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(text(&case, "SELECT tool FROM collections"), "portal_export");
    let f = row(&report, DETAIL_REL);
    assert_eq!(
        f.artifact_id.as_deref(),
        Some("portal.message_trace_detail")
    );
    assert_eq!(f.status, FileStatus::Parsed);
    assert_eq!(text(&case, "SELECT encoding FROM source_files"), "utf-16le");
}

#[test]
fn summary_report_stays_the_summary_report() {
    let summary = "origin_timestamp_utc,sender_address,recipient_status,message_subject,total_bytes,message_id,network_message_id,original_client_ip,directionality,connector_id,delivery_priority\r\n";
    assert_eq!(
        artifact(PortalExport, &utf16le_no_bom(summary)),
        Some("portal.message_trace")
    );
    // The detail columns missing one of the four required ones is not the detail report.
    let partial = "date_time_utc,network_message_id,event_id,recipient_address\r\n";
    assert_eq!(artifact(PortalExport, partial.as_bytes()), None);
}

// ---- events and collapse ----

#[test]
fn every_event_is_loaded_and_the_message_collapses_to_one_row_per_recipient() {
    let (case, report) = case_of(&report(&main_message()));
    let f = row(&report, DETAIL_REL);
    assert_eq!(
        f.artifact_id.as_deref(),
        Some("portal.message_trace_detail")
    );

    assert_eq!(count(&case, "SELECT count(*) FROM message_trace_events"), 6);
    assert_eq!(
        count(
            &case,
            "SELECT count(DISTINCT record_key) FROM message_trace_events WHERE record_key LIKE 'csvrow:%'"
        ),
        6
    );
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 2);

    // Every column of the RECEIVE event.
    let got = text(
        &case,
        "SELECT concat_ws('|',
            CAST(epoch_us(event_time) AS VARCHAR), CAST(time_tz_assumed AS VARCHAR),
            network_message_id, internal_message_id, internet_message_id, event_id, source,
            coalesce(source_context, '<null>'), sender, CAST(recipients AS VARCHAR),
            coalesce(related_recipient, '<null>'), recipient_status, client_ip, client_hostname,
            coalesce(server_ip, '<null>'), server_hostname,
            coalesce(original_client_ip, '<null>'), original_server_ip, connector_id,
            CAST(total_bytes AS VARCHAR), CAST(recipient_count AS VARCHAR), reference,
            replace(replace(subject, chr(13), '\\r'), chr(10), '\\n'), return_path, message_info,
            directionality, tenant_id, custom_data)
         FROM message_trace_events WHERE event_id = 'RECEIVE'",
    );
    let t = epoch_us(2026, 8, 4, 17, 53, 9, 629_000);
    assert_eq!(
        got,
        format!(
            "{t}|false|{NMID_LOWER}|1234567890|<m1@contoso.example>|RECEIVE|SMTP|<null>|\
             alice@contoso.example|[\"bob@contoso.example\",\"carol@contoso.example\"]|<null>|\
             250 2.1.5 Recipient OK|2001:db8::10|mail-ch2.contoso.example|<null>|\
             srv1.contoso.example|<null>|198.51.100.1|Default frontend|2048|2|ref-1|\
             Wire details, urgent\\r\\nplease read|alice@contoso.example|S:Foo=Bar;S:Baz=Qux|\
             Originating|bbbbbbbb-0000-4000-8000-000000000002|S:Cd=1;S:Ce=2"
        )
    );
    // The original text of the unnormalized addresses stays in raw.
    assert_eq!(
        text(
            &case,
            "SELECT json_extract_string(raw, '$.server_ip') || ' ' ||
                    json_extract_string(raw, '$.original_client_ip')
             FROM message_trace_events WHERE event_id = 'RECEIVE'"
        ),
        "fe80::1%3 fe80::5%2"
    );

    // The forwarding event.
    assert_eq!(
        text(
            &case,
            "SELECT source_context || '|' || related_recipient || '|' || CAST(recipients AS VARCHAR)
             FROM message_trace_events WHERE event_id = 'DUPLICATEREDIRECT'"
        ),
        "Forwarding SMTP Address|dave@fabrikam.example|[\"bob@contoso.example\"]"
    );

    // message_trace: one row per recipient.
    let cols = "record_key || '|' || message_trace_id || '|' || CAST(epoch_us(received) AS VARCHAR)
        || '|' || CAST(time_tz_assumed AS VARCHAR) || '|' || sender || '|' ||
        replace(replace(subject, chr(13), '\\r'), chr(10), '\\n') || '|' || coalesce(status, '<null>')
        || '|' || from_ip || '|' || coalesce(to_ip, '<null>') || '|' || CAST(size_bytes AS VARCHAR)
        || '|' || internet_message_id || '|' || coalesce(organization, '<null>') || '|' ||
        direction || '|' || connector_id";
    let common = format!(
        "{NMID_LOWER}|{t}|false|alice@contoso.example|Wire details, urgent\\r\\nplease read|"
    );
    let tail = "|203.0.113.50|<null>|2100|<m1@contoso.example>|<null>|Originating|Default frontend";
    assert_eq!(
        text(
            &case,
            &format!("SELECT {cols} FROM message_trace WHERE recipient = 'bob@contoso.example'")
        ),
        format!("{NMID_LOWER}|bob@contoso.example|{common}DUPLICATEREDIRECT{tail}")
    );
    assert_eq!(
        text(
            &case,
            &format!("SELECT {cols} FROM message_trace WHERE recipient = 'carol@contoso.example'")
        ),
        format!("{NMID_LOWER}|carol@contoso.example|{common}DELIVER{tail}")
    );
    // The collapsed raw is small: the counts and the chosen values, not every event.
    let raw = text(
        &case,
        "SELECT CAST(raw AS VARCHAR) FROM message_trace WHERE recipient = 'carol@contoso.example'",
    );
    let raw: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(raw["network_message_id"], NMID_LOWER);
    assert_eq!(raw["recipient"], "carol@contoso.example");
    assert_eq!(raw["events"], 6);
    assert_eq!(raw["event_id"], "DELIVER");
    assert!(raw.to_string().len() < 1500, "{raw}");
}

#[test]
fn the_last_relevant_event_by_time_decides_the_status_and_ties_go_to_the_later_row() {
    const X: &str = "cccccccc-0000-4000-8000-00000000000a";
    const Y: &str = "cccccccc-0000-4000-8000-00000000000b";
    const Z: &str = "cccccccc-0000-4000-8000-00000000000c";
    let e = |at: &str, id: &str, nmid: &str, to: &str| {
        ev(&[
            ("date_time_utc", at),
            ("event_id", id),
            ("network_message_id", nmid),
            ("recipient_address", to),
            ("sender_address", "alice@contoso.example"),
        ])
    };
    let events = vec![
        // x: FAIL (t2) is after DEFER (t1) although it comes first in the file.
        e(
            "2026-08-04T10:00:02.0000000Z",
            "FAIL",
            X,
            "x@contoso.example",
        ),
        e(
            "2026-08-04T10:00:01.0000000Z",
            "DEFER",
            X,
            "x@contoso.example",
        ),
        // y: DELIVER and FAIL at the same time: the later row of the file wins.
        e(
            "2026-08-04T10:00:03.0000000Z",
            "DELIVER",
            Y,
            "y@contoso.example",
        ),
        e(
            "2026-08-04T10:00:03.0000000Z",
            "FAIL",
            Y,
            "y@contoso.example",
        ),
        // z: FAIL and DELIVER at the same time, DELIVER later in the file.
        e(
            "2026-08-04T10:00:04.0000000Z",
            "FAIL",
            Z,
            "z@contoso.example",
        ),
        e(
            "2026-08-04T10:00:04.0000000Z",
            "DELIVER",
            Z,
            "z@contoso.example",
        ),
        // Events outside the status set never decide: w has only a RECEIVE and a RESOLVE.
        e(
            "2026-08-04T10:00:05.0000000Z",
            "RECEIVE",
            "cccccccc-0000-4000-8000-00000000000d",
            "w@contoso.example",
        ),
        e(
            "2026-08-04T10:00:06.0000000Z",
            "RESOLVE",
            "cccccccc-0000-4000-8000-00000000000d",
            "w@contoso.example",
        ),
        // A message whose events name no recipient has events but no message_trace row.
        e(
            "2026-08-04T10:00:07.0000000Z",
            "RECEIVE",
            "cccccccc-0000-4000-8000-00000000000e",
            "",
        ),
    ];
    let (case, _) = case_of(&report(&events));
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace_events"), 9);
    assert_eq!(
        statuses(&case),
        "w@contoso.example=NULL,x@contoso.example=FAIL,y@contoso.example=FAIL,z@contoso.example=DELIVER"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 4);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM message_trace_events WHERE recipients IS NULL"
        ),
        1
    );
}

#[test]
fn a_status_event_names_the_recipient_only_by_recipient_address() {
    // The DELIVER names carol; bob only appears as related_recipient_address of it.
    let events = vec![
        ev(&[
            ("date_time_utc", "2026-08-04T10:00:00.0000000Z"),
            ("event_id", "RECEIVE"),
            ("network_message_id", NMID),
            (
                "recipient_address",
                "bob@contoso.example;carol@contoso.example",
            ),
        ]),
        ev(&[
            ("date_time_utc", "2026-08-04T10:00:01.0000000Z"),
            ("event_id", "DELIVER"),
            ("network_message_id", NMID),
            ("recipient_address", "carol@contoso.example"),
            ("related_recipient_address", "bob@contoso.example"),
        ]),
    ];
    let (case, _) = case_of(&report(&events));
    assert_eq!(
        statuses(&case),
        "bob@contoso.example=NULL,carol@contoso.example=DELIVER"
    );
}

#[test]
fn a_recipient_cell_with_several_addresses_splits() {
    let events = vec![ev(&[
        ("date_time_utc", "2026-08-04T10:00:00.0000000Z"),
        ("event_id", "DELIVER"),
        ("network_message_id", NMID),
        (
            "recipient_address",
            " A@x.example ; b@x.example;;a@x.example ",
        ),
    ])];
    let (case, _) = case_of(&report(&events));
    assert_eq!(
        text(
            &case,
            "SELECT CAST(recipients AS VARCHAR) FROM message_trace_events"
        ),
        "[\"a@x.example\",\"b@x.example\",\"a@x.example\"]"
    );
    // The collapse has one row per distinct recipient.
    assert_eq!(statuses(&case), "a@x.example=DELIVER,b@x.example=DELIVER");
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 2);
}

#[test]
fn quoted_cells_with_commas_and_newlines_survive_in_both_encodings() {
    for bytes in [
        utf16le_no_bom(&report_text(&main_message(), false)),
        utf16le_bom(&report_text(&main_message(), false)),
        utf8_bom(&report_text(&main_message(), false)),
    ] {
        let (case, _) = case_of(&bytes);
        assert_eq!(count(&case, "SELECT count(*) FROM message_trace_events"), 6);
        assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 2);
        assert_eq!(
            text(
                &case,
                "SELECT subject FROM message_trace_events WHERE event_id = 'RECEIVE'"
            ),
            SUBJECT
        );
        assert_eq!(
            text(
                &case,
                "SELECT DISTINCT subject FROM message_trace WHERE subject IS NOT NULL"
            ),
            SUBJECT
        );
    }
}

// ---- repeats ----

#[test]
fn the_same_events_in_two_downloads_are_one_row_with_two_sightings() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("downloads");
    fixtures::write(&folder, "a.csv", &report(&main_message()));
    // The second download has its columns in the opposite order and a byte-order mark.
    fixtures::write(
        &folder,
        "b.csv",
        &utf16le_bom(&report_text(&main_message(), true)),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace_events"), 6);
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'message_trace_events'"
        ),
        12
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'message_trace'"
        ),
        4
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM (SELECT record_key FROM record_sources
              WHERE table_name = 'message_trace_events' GROUP BY 1 HAVING count(*) = 2)"
        ),
        6
    );
}

#[test]
fn identical_rows_inside_one_file_are_one_row_with_two_sightings() {
    let events = vec![e_agentinfo(), e_agentinfo()];
    let (case, _) = case_of(&report(&events));
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace_events"), 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'message_trace_events'"
        ),
        2
    );
}

// ---- merging with the summary report ----

fn summary_text() -> String {
    let header = csv_line(&[
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
    ]);
    header
        + &csv_line(&[
            "2026-08-04T17:53:09.0000000Z",
            "alice@contoso.example",
            "bob@contoso.example##Delivered",
            "Wire details (summary)",
            "4096",
            "<m1@contoso.example>",
            NMID,
            "",
            "Originating",
            "",
            "Normal",
        ])
}

/// One detail event for bob that leaves `directionality` empty and `connector_id`, `from_ip` set.
fn detail_for_merge() -> Vec<u8> {
    report(&[ev(&[
        ("date_time_utc", "2026-08-04T17:53:11.0000000Z"),
        ("event_id", "DELIVER"),
        ("network_message_id", NMID),
        ("message_id", "<m1@contoso.example>"),
        ("recipient_address", "bob@contoso.example"),
        ("sender_address", "alice@contoso.example"),
        ("message_subject", "Wire details (detail)"),
        ("total_bytes", "1000"),
        ("connector_id", "Default frontend"),
        ("original_client_ip", "203.0.113.50"),
    ])])
}

const MERGE_SQL: &str =
    "SELECT concat_ws('|', status, subject, CAST(epoch_us(received) AS VARCHAR),
    CAST(size_bytes AS VARCHAR), direction, connector_id, from_ip) FROM message_trace";

#[test]
fn a_summary_row_loaded_first_keeps_its_values_and_the_detail_only_fills_nulls() {
    let mut case = Case::in_memory().unwrap();
    let a = tempfile::tempdir().unwrap();
    fixtures::write(
        &a.path().join("one"),
        SUMMARY_REL,
        &utf16le_no_bom(&summary_text()),
    );
    ingest_into(&mut case, a.path());
    let b = tempfile::tempdir().unwrap();
    fixtures::write(&b.path().join("two"), DETAIL_REL, &detail_for_merge());
    let report = ingest_into(&mut case, b.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 1);
    assert_eq!(
        text(&case, MERGE_SQL),
        format!(
            "Delivered|Wire details (summary)|{}|4096|Originating|Default frontend|203.0.113.50",
            epoch_us(2026, 8, 4, 17, 53, 9, 0)
        )
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
fn a_detail_row_loaded_first_wins_and_the_summary_only_fills_nulls() {
    let mut case = Case::in_memory().unwrap();
    let a = tempfile::tempdir().unwrap();
    fixtures::write(&a.path().join("one"), DETAIL_REL, &detail_for_merge());
    ingest_into(&mut case, a.path());
    let b = tempfile::tempdir().unwrap();
    fixtures::write(
        &b.path().join("two"),
        SUMMARY_REL,
        &utf16le_no_bom(&summary_text()),
    );
    let report = ingest_into(&mut case, b.path());
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 1);
    assert_eq!(
        text(&case, MERGE_SQL),
        format!(
            "DELIVER|Wire details (detail)|{}|1000|Originating|Default frontend|203.0.113.50",
            epoch_us(2026, 8, 4, 17, 53, 11, 0)
        )
    );
}

// ---- verify, availability ----

#[test]
fn verify_succeeds_on_an_event_row_and_a_collapsed_row() {
    // The files must still exist for verify to re-read them.
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(
        &dir.path().join("downloads"),
        DETAIL_REL,
        &report(&main_message()),
    );
    let (case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let key = text(
        &case,
        "SELECT record_key FROM message_trace_events WHERE event_id = 'RECEIVE'",
    );
    assert!(key.starts_with("csvrow:"));
    let v = verify_record(&case, "message_trace_events", &key, None).unwrap();
    assert!(v.ok, "{v:#?}");
    assert_eq!(v.sightings.len(), 1);

    let key = text(
        &case,
        "SELECT record_key FROM message_trace WHERE recipient = 'bob@contoso.example'",
    );
    assert_eq!(key, format!("{NMID_LOWER}|bob@contoso.example"));
    let v = verify_record(&case, "message_trace", &key, None).unwrap();
    assert!(v.ok, "{v:#?}");
    assert_eq!(v.sightings.len(), 1);
}

#[test]
fn availability_counts_the_detail_report_for_both_evidence_sources() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(
        &dir.path().join("downloads"),
        DETAIL_REL,
        &report(&main_message()),
    );
    let (mut case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    let as_of = Utc.with_ymd_and_hms(2026, 8, 30, 0, 0, 0).unwrap();
    refresh(
        &mut case,
        &ProfileOptions {
            as_of: Some(as_of),
            ..Default::default()
        },
    )
    .unwrap();
    let rows = compute(case.conn(), as_of).unwrap();
    let find = |id: &str| {
        rows.iter()
            .find(|r| r.evidence == id)
            .unwrap_or_else(|| panic!("no {id} row"))
    };
    let events = find("message_trace_events");
    assert_eq!(events.status, "collected", "{events:?}");
    assert_eq!(events.rows, 6);
    let trace = find("message_trace");
    assert_eq!(trace.status, "collected", "{trace:?}");
    assert_eq!(trace.rows, 2);
}

#[test]
fn a_folder_holding_only_the_detail_report_resolves_to_the_tenant_in_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(
        &dir.path().join("downloads"),
        DETAIL_REL,
        &report(&main_message()),
    );
    let (mut case, report) = ingest(dir.path());
    assert!(!report.has_errors(), "{report:#?}");
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        text(&case, "SELECT tenant_key FROM collections"),
        "bbbbbbbb-0000-4000-8000-000000000002"
    );
    assert_eq!(
        text(&case, "SELECT tenant_id_source FROM tenant"),
        "message_trace_tenant"
    );
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

#[test]
fn every_batch_size_stores_what_one_batch_stores() {
    // Events are streamed in batches and the collapsed message rows are loaded after them: two interleaved
    // messages, a repeated event row (a duplicate), with batches of 1-3 the events and the message rows both cross
    // batch boundaries.
    let other = "CCCCCCCC-0000-4000-8000-000000000003";
    let second: Vec<Ev> = main_message()
        .into_iter()
        .map(|e| {
            e.into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        if k == "network_message_id" {
                            other.to_string()
                        } else {
                            v
                        },
                    )
                })
                .collect()
        })
        .collect();
    let mut events = Vec::new();
    for (a, b) in main_message().into_iter().zip(second) {
        events.push(a);
        events.push(b);
    }
    events.push(e_receive());
    let dir = tempfile::tempdir().unwrap();
    fixtures::write(&dir.path().join("downloads"), DETAIL_REL, &report(&events));
    let run = |batch: usize| {
        let mut case = Case::in_memory().unwrap();
        let opts = IngestOptions {
            batch_rows: batch,
            ..IngestOptions::default()
        };
        let report = ingest_path(&mut case, dir.path(), &ParserRegistry::builtin(), &opts).unwrap();
        let f = row(&report, DETAIL_REL);
        let file = format!(
            "{:?} {} {} {} {} {:?}",
            f.status,
            f.records_read,
            f.records_loaded,
            f.records_duplicate,
            f.records_error,
            f.warnings
        );
        (all_tables(&case), file)
    };
    let (want_tables, want_file) = run(usize::MAX);
    // 13 event rows (12 + the repeated RECEIVE, a duplicate) and the message rows of two messages.
    let traces = want_tables
        .iter()
        .find(|(t, ..)| t == "message_trace")
        .unwrap()
        .1;
    assert!(traces >= 4, "{traces} message rows");
    assert!(want_file.starts_with("Parsed "), "{want_file}");
    assert!(
        want_file.contains(" 1 0 "),
        "one duplicate, no error: {want_file}"
    );
    for batch in [1, 2, 3] {
        let (tables, file) = run(batch);
        assert_eq!(file, want_file, "batch {batch}: file report");
        assert_eq!(tables, want_tables, "batch {batch}: tables");
    }
}
