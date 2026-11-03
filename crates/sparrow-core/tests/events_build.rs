//! Task 1 of the investigate tabs: the `events` table (migration 0025) and its normalized Entra session, device,
//! owner and IP columns.

use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::case::events::{self, SOURCES};
use sparrow_core::detect::test::insert_record;
use sparrow_core::fixtures::portal::portal_tree;
use sparrow_core::fixtures::ual;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::profile::{ProfileOptions, refresh};
use std::collections::BTreeMap;

const T: &str = "contoso";
const UAL_A: &str = "a0000001-0000-4000-8000-000000000001";
const UAL_B: &str = "a0000002-0000-4000-8000-000000000002";
const UAL_C: &str = "a0000003-0000-4000-8000-000000000003";
/// An Exchange session: the top-level SessionId of mailbox events.
const EXCHANGE_SESSION: &str = "11111111-1111-4111-8111-111111111111";
/// An Entra session, with hex letters so lower-casing shows.
const ENTRA_SESSION_UPPER: &str = "2222AAAA-2222-4222-8222-22222222BBBB";
const ENTRA_SESSION: &str = "2222aaaa-2222-4222-8222-22222222bbbb";
const DEVICE_UPPER: &str = "D3D3D3D3-0000-4000-8000-00000000ABCD";
const DEVICE: &str = "d3d3d3d3-0000-4000-8000-00000000abcd";
/// The directory object id of that device (what directory audit targets carry), and one no devices row knows.
const DEVICE_OBJECT_UPPER: &str = "0B1EC700-0000-4000-8000-00000000ABCD";
const DEVICE_OBJECT: &str = "0b1ec700-0000-4000-8000-00000000abcd";
const UNKNOWN_OBJECT: &str = "0b1ec700-0000-4000-8000-0000000000ff";

fn put(case: &Case, table: &str, fields: Value) {
    insert_record(case, T, table, &fields, "events_build").unwrap();
}

/// One ual_events row, as the normalizer stores it: `session_id` prefers the top-level SessionId.
fn put_ual(case: &Case, record_id: &str, audit: Value) {
    let session = audit["SessionId"]
        .as_str()
        .or_else(|| audit["AppAccessContext"]["AADSessionId"].as_str());
    put(
        case,
        "ual_events",
        json!({
            "record_id": record_id, "event_time": "2026-09-01T10:00:00Z", "workload": audit["Workload"],
            "operation": audit["Operation"], "user_upn": audit["UserId"], "mailbox_upn": audit["MailboxOwnerUPN"],
            "session_id": session, "audit_data": audit
        }),
    );
}

fn sources(case: &Case) -> BTreeMap<String, i64> {
    let mut st = case
        .conn()
        .prepare("SELECT source, count(*) FROM events GROUP BY 1")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

/// `column` of the one events row `(source_table, record_key)`.
fn cell(case: &Case, source_table: &str, key: &str, column: &str) -> Option<String> {
    case.conn()
        .query_row(
            &format!(
                "SELECT CAST({column} AS VARCHAR) FROM events WHERE source_table = ? AND record_key = ?"
            ),
            [source_table, key],
            |r| r.get(0),
        )
        .unwrap()
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// One record in each of the 11 event tables (the sign-in table for each of its 4 event types), plus rows `events` must not list.
fn one_of_everything() -> Case {
    let case = Case::in_memory().unwrap();
    put_ual(
        &case,
        UAL_A,
        json!({"Workload": "Exchange", "Operation": "FileDownloaded", "UserId": "alice@contoso.example"}),
    );
    // A MailItemsAccessed child of the UAL record: part of that record, not an event of its own.
    put(
        &case,
        "mail_items_accessed",
        json!({"record_id": UAL_A, "item_ordinal": 0, "item_key": "child-1"}),
    );
    // A Sessions-report row without a raw record: this one is an event.
    put(
        &case,
        "mail_items_accessed",
        json!({"item_key": "mia-1", "event_time": "2026-09-01T10:01:00Z", "user_upn": "alice@contoso.example"}),
    );
    put(
        &case,
        "signins",
        json!({"record_key": "si-i", "event_time": "2026-09-01T10:02:00Z", "event_type": "interactive"}),
    );
    put(
        &case,
        "signins",
        json!({"record_key": "si-n", "event_time": "2026-09-01T10:03:00Z", "event_type": "noninteractive"}),
    );
    put(
        &case,
        "signins",
        json!({"record_key": "si-s", "event_time": "2026-09-01T10:03:30Z", "event_type": "service_principal"}),
    );
    put(
        &case,
        "signins",
        json!({"record_key": "si-m", "event_time": "2026-09-01T10:03:40Z", "event_type": "managed_identity"}),
    );
    put(
        &case,
        "directory_audits",
        json!({"record_key": "da-1", "event_time": "2026-09-01T10:04:00Z", "activity": "Add user"}),
    );
    put(
        &case,
        "message_trace",
        json!({"record_key": "mt-1", "received": "2026-09-01T10:05:00Z"}),
    );
    put(
        &case,
        "message_trace_events",
        json!({"record_key": "mte-1", "event_time": "2026-09-01T10:05:01Z", "event_id": "RECEIVE"}),
    );
    put(
        &case,
        "mailbox_audit_legacy",
        json!({"record_key": "ma-1", "event_time": "2026-09-01T10:06:00Z"}),
    );
    put(
        &case,
        "admin_audit_events",
        json!({"record_key": "aa-1", "run_time": "2026-09-01T10:07:00Z"}),
    );
    put(
        &case,
        "risk_detections",
        json!({"record_key": "rd-1", "detected_time": "2026-09-01T10:08:00Z"}),
    );
    put(
        &case,
        "azure_activity",
        json!({"record_key": "az-1", "event_time": "2026-09-01T10:09:00Z"}),
    );
    put(
        &case,
        "security_alerts",
        json!({"record_key": "sa-1", "created_time": "2026-09-01T10:10:00Z"}),
    );
    case
}

#[test]
fn every_event_source_gets_one_row_per_record() {
    let case = one_of_everything();
    let written = events::rebuild(case.conn()).unwrap();
    // One row per source, except the service sign-in source: a service principal and a managed identity.
    let mut expected: BTreeMap<String, i64> = SOURCES.iter().map(|s| (s.to_string(), 1)).collect();
    expected.insert("signin_service".into(), 2);
    assert_eq!(SOURCES.len(), 13);
    assert_eq!(sources(&case), expected);
    assert_eq!(written, 14);
    assert_eq!(count(&case, "SELECT count(*) FROM events"), 14);
    // The child row of the UAL record is not an event; the Sessions-report row is.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM events WHERE source_table = 'mail_items_accessed' AND record_key = 'child-1'"
        ),
        0
    );
    assert_eq!(
        cell(&case, "mail_items_accessed", "mia-1", "source").as_deref(),
        Some("mail_items_accessed")
    );
    assert_eq!(
        cell(&case, "signins", "si-i", "source").as_deref(),
        Some("signin_interactive")
    );
    assert_eq!(
        cell(&case, "signins", "si-n", "source").as_deref(),
        Some("signin_noninteractive")
    );
    for key in ["si-s", "si-m"] {
        assert_eq!(
            cell(&case, "signins", key, "source").as_deref(),
            Some("signin_service")
        );
    }
    // The time comes from each table's own column.
    assert_eq!(
        cell(&case, "security_alerts", "sa-1", "epoch(event_time)").as_deref(),
        Some("1788257400.0")
    );
}

static NEXT_EXPORT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

/// Ingests UAL records through the real pipeline (a Purview export), so the stored shape is the parser's.
fn ingest_purview(case: &mut Case, rows: &[Value]) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    let text = ual::PURVIEW_HEADER.to_string()
        + &rows
            .iter()
            .map(|a| ual::purview_row("2026-09-01T10:00:00.0000000Z", a))
            .collect::<String>();
    sparrow_core::fixtures::write(
        &root,
        &format!(
            "9b2e6f1a-3c4d-4e5f-8a9b-{:012}.csv",
            NEXT_EXPORT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ),
        text.as_bytes(),
    );
    let report = ingest_path(
        case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
}

fn audit(id: &str, workload: &str, record_type: i64, operation: &str, extra: Value) -> Value {
    let mut v = json!({
        "CreationTime": "2026-09-01T10:00:00", "Id": id, "Operation": operation, "OrganizationId": ual::ORG_ID,
        "RecordType": record_type, "ResultStatus": "Succeeded", "UserKey": "k", "UserType": 0, "Version": 1,
        "Workload": workload, "UserId": "alice@contoso.example", "ClientIP": "203.0.113.10"
    });
    v.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    v
}

#[test]
fn ual_entra_session_comes_from_aad_session_id_not_exchange_session() {
    let mut case = Case::in_memory().unwrap();
    ingest_purview(
        &mut case,
        &[
            // Mailbox event: top-level SessionId is the Exchange session, AADSessionId the Entra one.
            audit(
                UAL_A,
                "Exchange",
                50,
                "MailItemsAccessed",
                json!({"SessionId": EXCHANGE_SESSION, "MailboxOwnerUPN": "alice@contoso.example",
                       "AppAccessContext": {"AADSessionId": ENTRA_SESSION_UPPER}}),
            ),
            // Mailbox event with an Exchange session only: no Entra session to report.
            audit(
                UAL_B,
                "Exchange",
                50,
                "MailItemsAccessed",
                json!({"SessionId": EXCHANGE_SESSION, "MailboxOwnerUPN": "alice@contoso.example"}),
            ),
        ],
    );
    // The premise: what the normalizer stores in ual_events.session_id is the Exchange session.
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM ual_events WHERE session_id = '{EXCHANGE_SESSION}'")
        ),
        2
    );
    // A sign-in whose SessionId is upper case in the source, and a mailbox audit row with an Exchange session.
    put(
        &case,
        "signins",
        json!({"record_key": "si-1", "event_time": "2026-09-01T10:02:00Z", "event_type": "interactive",
               "session_id": ENTRA_SESSION_UPPER}),
    );
    put(
        &case,
        "mailbox_audit_legacy",
        json!({"record_key": "ma-1", "event_time": "2026-09-01T10:06:00Z", "session_id": EXCHANGE_SESSION}),
    );
    // A Sessions-report row: its session is the AuditData top-level SessionId, an Exchange session.
    put(
        &case,
        "mail_items_accessed",
        json!({"item_key": "mia-1", "event_time": "2026-09-01T10:01:00Z", "user_upn": "alice@contoso.example",
               "session_id": EXCHANGE_SESSION}),
    );
    events::rebuild(case.conn()).unwrap();
    assert_eq!(
        cell(&case, "ual_events", UAL_A, "entra_session_id").as_deref(),
        Some(ENTRA_SESSION)
    );
    assert_eq!(cell(&case, "ual_events", UAL_B, "entra_session_id"), None);
    assert_eq!(
        cell(&case, "signins", "si-1", "entra_session_id").as_deref(),
        Some(ENTRA_SESSION)
    );
    assert_eq!(
        cell(&case, "mailbox_audit_legacy", "ma-1", "entra_session_id"),
        None
    );
    assert_eq!(
        cell(&case, "mail_items_accessed", "mia-1", "entra_session_id"),
        None
    );
    // Exactly the two Entra-session rows carry one.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM events WHERE entra_session_id IS NOT NULL"
        ),
        2
    );
}

#[test]
fn sts_logon_session_comes_from_device_properties() {
    let mut case = Case::in_memory().unwrap();
    ingest_purview(
        &mut case,
        &[audit(
            UAL_A,
            "AzureActiveDirectory",
            15,
            "UserLoggedIn",
            json!({"DeviceProperties": [
                {"Name": "Id", "Value": DEVICE_UPPER}, {"Name": "SessionId", "Value": ENTRA_SESSION_UPPER}]}),
        )],
    );
    events::rebuild(case.conn()).unwrap();
    assert_eq!(
        cell(&case, "ual_events", UAL_A, "entra_session_id").as_deref(),
        Some(ENTRA_SESSION)
    );
}

#[test]
fn device_id_and_name_from_signins_ual_and_directory_audit_targets_resolved_through_devices() {
    let mut case = Case::in_memory().unwrap();
    ingest_purview(
        &mut case,
        &[
            // DeviceProperties as the Name/Value array, with the keys' case varied by source.
            audit(
                UAL_A,
                "AzureActiveDirectory",
                15,
                "UserLoggedIn",
                json!({"DeviceProperties": [
                    {"Name": "OS", "Value": "Windows10"}, {"Name": "Id", "Value": DEVICE_UPPER},
                    {"Name": "DisplayName", "Value": "LAPTOP-01"}]}),
            ),
            // The same array as a string, which the UAL normalizer also accepts.
            audit(
                UAL_B,
                "AzureActiveDirectory",
                15,
                "UserLoggedIn",
                json!({"DeviceProperties": json!([
                    {"Name": "Id", "Value": DEVICE_UPPER}, {"Name": "DisplayName", "Value": "LAPTOP-01"}]).to_string()}),
            ),
            // An all-zero id is no device.
            audit(
                UAL_C,
                "AzureActiveDirectory",
                15,
                "UserLoggedIn",
                json!({"DeviceProperties": [{"Name": "Id", "Value": "00000000-0000-0000-0000-000000000000"}]}),
            ),
        ],
    );
    put(
        &case,
        "signins",
        json!({"record_key": "si-1", "event_time": "2026-09-01T10:02:00Z", "event_type": "interactive",
               "device": {"device_id": DEVICE_UPPER, "display_name": "LAPTOP-01", "os": null, "browser": null,
                          "is_compliant": null, "is_managed": null, "trust_type": null}}),
    );
    // Hawk writes PascalCase target keys, Graph REST camelCase; only the Device target counts.
    put(
        &case,
        "directory_audits",
        json!({"record_key": "da-pascal", "event_time": "2026-09-01T10:04:00Z", "activity": "Register device",
               "targets": json!([
                   {"Type": "User", "Id": "u-1", "UserPrincipalName": "alice@contoso.example"},
                   {"Type": "Device", "Id": DEVICE_OBJECT_UPPER, "DisplayName": "LAPTOP-01"}]).to_string()}),
    );
    put(
        &case,
        "directory_audits",
        json!({"record_key": "da-camel", "event_time": "2026-09-01T10:05:00Z", "activity": "Register device",
               "targets": json!([{"type": "Device", "id": DEVICE_OBJECT_UPPER, "displayName": "LAPTOP-01"}]).to_string()}),
    );
    put(
        &case,
        "directory_audits",
        json!({"record_key": "da-user", "event_time": "2026-09-01T10:06:00Z", "activity": "Add user",
               "targets": json!([{"Type": "User", "Id": "u-1"}]).to_string()}),
    );
    // A device no devices row resolves: the object id is kept, the device id stays empty.
    put(
        &case,
        "directory_audits",
        json!({"record_key": "da-unknown", "event_time": "2026-09-01T10:07:00Z", "activity": "Register device",
               "targets": json!([{"Type": "Device", "Id": UNKNOWN_OBJECT, "DisplayName": "LAPTOP-02"}]).to_string()}),
    );
    put(
        &case,
        "devices",
        json!({"record_key": DEVICE, "device_id": DEVICE, "object_id": DEVICE_OBJECT}),
    );
    events::rebuild(case.conn()).unwrap();
    for (table, key) in [
        ("ual_events", UAL_A),
        ("ual_events", UAL_B),
        ("signins", "si-1"),
        ("directory_audits", "da-pascal"),
        ("directory_audits", "da-camel"),
    ] {
        assert_eq!(
            cell(&case, table, key, "device_id").as_deref(),
            Some(DEVICE),
            "{table} {key}"
        );
        assert_eq!(
            cell(&case, table, key, "device_name").as_deref(),
            Some("LAPTOP-01"),
            "{table} {key}"
        );
    }
    for key in ["da-pascal", "da-camel"] {
        assert_eq!(
            cell(&case, "directory_audits", key, "device_object_id").as_deref(),
            Some(DEVICE_OBJECT),
            "{key}"
        );
    }
    assert_eq!(
        cell(&case, "directory_audits", "da-unknown", "device_id"),
        None
    );
    assert_eq!(
        cell(&case, "directory_audits", "da-unknown", "device_object_id").as_deref(),
        Some(UNKNOWN_OBJECT)
    );
    assert_eq!(
        cell(&case, "directory_audits", "da-unknown", "device_name").as_deref(),
        Some("LAPTOP-02")
    );
    // Sign-ins and UAL carry the device id, never the object id.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM events WHERE device_object_id IS NOT NULL"
        ),
        3
    );
    // The zero GUID, a user target and every other table give no device.
    assert_eq!(cell(&case, "ual_events", UAL_C, "device_id"), None);
    assert_eq!(
        cell(&case, "directory_audits", "da-user", "device_id"),
        None
    );
    assert_eq!(
        cell(&case, "directory_audits", "da-user", "device_name"),
        None
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM events WHERE device_id IS NOT NULL"
        ),
        5
    );
}

#[test]
fn owner_upn_for_mailbox_and_message_trace_rows() {
    let mut case = Case::in_memory().unwrap();
    ingest_purview(
        &mut case,
        &[
            audit(
                UAL_A,
                "Exchange",
                50,
                "MailItemsAccessed",
                json!({"MailboxOwnerUPN": "Shared@Contoso.example", "UserId": "Bob@contoso.example"}),
            ),
            // Not a MailItemsAccessed event: no owner, even though a mailbox is named.
            audit(
                UAL_B,
                "Exchange",
                2,
                "Send",
                json!({"MailboxOwnerUPN": "Shared@Contoso.example"}),
            ),
        ],
    );
    put(
        &case,
        "mail_items_accessed",
        json!({"item_key": "mia-1", "event_time": "2026-09-01T10:01:00Z", "user_upn": "alice@contoso.example"}),
    );
    put(
        &case,
        "mailbox_audit_legacy",
        json!({"record_key": "ma-1", "event_time": "2026-09-01T10:06:00Z", "mailbox_upn": "Carol@Contoso.example",
               "logon_user": "Dave@Contoso.example"}),
    );
    put(
        &case,
        "message_trace",
        json!({"record_key": "mt-1", "received": "2026-09-01T10:05:00Z", "sender": "Erin@Contoso.example",
               "recipient": "Frank@Fabrikam.example"}),
    );
    put(
        &case,
        "message_trace_events",
        json!({"record_key": "mte-1", "event_time": "2026-09-01T10:05:01Z", "event_id": "DELIVER",
               "sender": "erin@contoso.example", "recipients": ["frank@fabrikam.example", "gina@fabrikam.example"]}),
    );
    put(
        &case,
        "signins",
        json!({"record_key": "si-1", "event_time": "2026-09-01T10:02:00Z", "event_type": "interactive",
               "user_upn": "alice@contoso.example"}),
    );
    events::rebuild(case.conn()).unwrap();
    let got: Vec<(String, String, Option<String>, Option<String>)> = {
        let mut st = case
            .conn()
            .prepare(
                "SELECT source_table, record_key, actor_upn, owner_upn FROM events ORDER BY source_table, record_key",
            )
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    let s = |x: &str| Some(x.to_string());
    let row = |t: &str, k: &str, a: Option<String>, o: Option<String>| {
        (t.to_string(), k.to_string(), a, o)
    };
    assert_eq!(
        got,
        vec![
            row(
                "mail_items_accessed",
                "mia-1",
                s("alice@contoso.example"),
                s("alice@contoso.example")
            ),
            row(
                "mailbox_audit_legacy",
                "ma-1",
                s("dave@contoso.example"),
                s("carol@contoso.example")
            ),
            row(
                "message_trace",
                "mt-1",
                s("erin@contoso.example"),
                s("frank@fabrikam.example")
            ),
            row(
                "message_trace_events",
                "mte-1",
                s("erin@contoso.example"),
                s("frank@fabrikam.example")
            ),
            row("signins", "si-1", s("alice@contoso.example"), None),
            row(
                "ual_events",
                UAL_A,
                s("bob@contoso.example"),
                s("shared@contoso.example")
            ),
            row("ual_events", UAL_B, s("alice@contoso.example"), None),
        ]
    );
}

#[test]
fn ip_prefix_v4_and_v6() {
    let case = Case::in_memory().unwrap();
    for (key, ip) in [
        ("v4", Some("203.0.113.45")),
        ("v6", Some("2001:db8:abcd:12::1")),
        ("v6-upper", Some("2001:DB8:ABCD:12::1")),
        ("none", None),
        ("junk", Some("not-an-ip")),
    ] {
        put(
            &case,
            "signins",
            json!({"record_key": key, "event_time": "2026-09-01T10:02:00Z", "event_type": "interactive", "ip": ip}),
        );
    }
    events::rebuild(case.conn()).unwrap();
    let want = [
        ("v4", Some("203.0.113.45"), Some("203.0.113.0/24")),
        (
            "v6",
            Some("2001:db8:abcd:12::1"),
            Some("2001:db8:abcd::/48"),
        ),
        (
            "v6-upper",
            Some("2001:db8:abcd:12::1"),
            Some("2001:db8:abcd::/48"),
        ),
        ("none", None, None),
        ("junk", Some("not-an-ip"), None),
    ];
    for (key, ip, prefix) in want {
        assert_eq!(cell(&case, "signins", key, "ip").as_deref(), ip, "{key} ip");
        assert_eq!(
            cell(&case, "signins", key, "ip_prefix").as_deref(),
            prefix,
            "{key} prefix"
        );
    }
}

#[test]
fn ip_kind_from_ip_intel() {
    let case = Case::in_memory().unwrap();
    for (key, ip) in [
        ("ms", "198.51.100.7"),
        ("private", "192.0.2.9"),
        ("hosting", "203.0.113.5"),
        ("plain", "203.0.113.99"),
        ("unknown", "203.0.113.200"),
    ] {
        put(
            &case,
            "signins",
            json!({"record_key": key, "event_time": "2026-09-01T10:02:00Z", "event_type": "interactive", "ip": ip}),
        );
    }
    case.conn()
        .execute_batch(
            "INSERT INTO ip_intel (ip, country_iso, asn, asn_org, is_hosting, is_microsoft, is_private) VALUES
                ('198.51.100.7', 'US', 8075, 'MICROSOFT-CORP', false, true, false),
                ('192.0.2.9', NULL, NULL, NULL, NULL, false, true),
                ('203.0.113.5', 'NG', 14061, 'DIGITALOCEAN-ASN', true, false, false),
                ('203.0.113.99', 'DE', 3320, 'DTAG', false, false, false)",
        )
        .unwrap();
    events::rebuild(case.conn()).unwrap();
    let want = [
        ("ms", Some("microsoft"), Some("US"), Some("8075")),
        ("private", Some("private"), None, None),
        ("hosting", Some("hosting"), Some("NG"), Some("14061")),
        ("plain", None, Some("DE"), Some("3320")),
        ("unknown", None, None, None),
    ];
    for (key, kind, country, asn) in want {
        assert_eq!(
            cell(&case, "signins", key, "ip_kind").as_deref(),
            kind,
            "{key} kind"
        );
        assert_eq!(
            cell(&case, "signins", key, "ip_country").as_deref(),
            country,
            "{key} country"
        );
        assert_eq!(
            cell(&case, "signins", key, "asn").as_deref(),
            asn,
            "{key} asn"
        );
    }
    assert_eq!(
        cell(&case, "signins", "hosting", "asn_org").as_deref(),
        Some("DIGITALOCEAN-ASN")
    );
}

#[test]
fn rebuild_is_idempotent_and_tracks_new_ingest() {
    let dir = tempfile::tempdir().unwrap();
    portal_tree(dir.path());
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    let first = count(&case, "SELECT count(*) FROM events");
    // The portal tree holds one UAL record and one message trace summary file.
    let evidence = count(
        &case,
        "SELECT (SELECT count(*) FROM ual_events) + (SELECT count(*) FROM message_trace)
              + (SELECT count(*) FROM message_trace_events)",
    );
    assert_eq!(first, evidence);
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 1);
    assert!(count(&case, "SELECT count(*) FROM message_trace") > 0);
    // The profile derived the tenant; every row carries it.
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM events WHERE tenant_key IS NULL"
        ),
        0
    );

    // Rebuilding changes nothing, by hand and again through the profile.
    assert_eq!(events::rebuild(case.conn()).unwrap() as i64, first);
    assert_eq!(count(&case, "SELECT count(*) FROM events"), first);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM events"), first);

    // One more UAL file adds exactly its two records.
    ingest_purview(&mut case, &[ual::login(), ual::mail_items_accessed()]);
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(count(&case, "SELECT count(*) FROM events"), first + 2);
    assert_eq!(
        count(&case, "SELECT count(*) FROM events WHERE source = 'ual'"),
        3
    );
    // The rebuilt rows carry what the new records say.
    assert_eq!(
        cell(&case, "ual_events", ual::ID_MIA, "entra_session_id").as_deref(),
        Some("aaaa0000-0000-4000-8000-00000000000a")
    );
}

#[test]
fn events_agree_with_the_timeline_view_on_shared_columns() {
    let mut case = one_of_everything();
    refresh(&mut case, &ProfileOptions::default()).unwrap();
    // The view has no message_trace_events rows; every other row of it is in events, with the same values.
    let shared = count(
        &case,
        "SELECT count(*) FROM timeline t JOIN events e USING (source_table, record_key)",
    );
    assert_eq!(shared, count(&case, "SELECT count(*) FROM timeline"));
    assert_eq!(shared, 13);
    let differing = count(
        &case,
        "SELECT count(*) FROM timeline t JOIN events e USING (source_table, record_key)
         WHERE NOT (t.event_time IS NOT DISTINCT FROM e.event_time
                AND CAST(t.category AS VARCHAR) IS NOT DISTINCT FROM CAST(e.category AS VARCHAR)
                AND t.operation IS NOT DISTINCT FROM e.operation
                AND lower(t.actor_upn) IS NOT DISTINCT FROM e.actor_upn
                AND t.target IS NOT DISTINCT FROM e.target
                AND t.ip IS NOT DISTINCT FROM e.ip
                AND t.user_agent IS NOT DISTINCT FROM e.user_agent
                AND t.summary IS NOT DISTINCT FROM e.summary)",
    );
    assert_eq!(differing, 0);
}

fn put_audit(case: &Case, key: &str, targets: Value, modified_properties: Option<Value>) {
    put(
        case,
        "directory_audits",
        json!({"record_key": key, "event_time": "2026-09-01T10:04:00Z", "activity": "Register device",
               "targets": targets.to_string(),
               "modified_properties": modified_properties.map(|v| v.to_string())}),
    );
}

fn audit_device(case: &Case, key: &str) -> (Option<String>, Option<String>, Option<String>) {
    (
        cell(case, "directory_audits", key, "device_id"),
        cell(case, "directory_audits", key, "device_object_id"),
        cell(case, "directory_audits", key, "device_name"),
    )
}

#[test]
fn directory_audit_device_id_from_modified_property_without_a_devices_row() {
    let case = Case::in_memory().unwrap();
    // The parser's flattened [{target, property, old, new}], new value JSON-quoted as Graph writes it.
    put_audit(
        &case,
        "da-prop",
        json!([{"Type": "Device", "Id": DEVICE_OBJECT_UPPER, "DisplayName": "LAPTOP-01"}]),
        Some(
            json!([{"target": "LAPTOP-01", "property": "TargetId.DeviceId",
                     "old": null, "new": format!("[\"{DEVICE_UPPER}\"]")}]),
        ),
    );
    // The property kept on the raw target, plain `DeviceId`.
    put_audit(
        &case,
        "da-raw",
        json!([{"Type": "Device", "Id": DEVICE_OBJECT_UPPER, "DisplayName": "LAPTOP-01",
                "ModifiedProperties": [{"DisplayName": "DeviceId", "NewValue": DEVICE_UPPER, "OldValue": null}]}]),
        None,
    );
    // Neither a property nor a devices row: only the object id.
    put_audit(
        &case,
        "da-none",
        json!([{"Type": "Device", "Id": DEVICE_OBJECT_UPPER, "DisplayName": "LAPTOP-01"}]),
        None,
    );
    assert_eq!(count(&case, "SELECT count(*) FROM devices"), 0);
    events::rebuild(case.conn()).unwrap();
    let some = |x: &str| Some(x.to_string());
    for key in ["da-prop", "da-raw"] {
        assert_eq!(
            audit_device(&case, key),
            (some(DEVICE), some(DEVICE_OBJECT), some("LAPTOP-01")),
            "{key}"
        );
    }
    assert_eq!(
        audit_device(&case, "da-none"),
        (None, some(DEVICE_OBJECT), some("LAPTOP-01"))
    );
}

#[test]
fn directory_audit_property_wins_over_the_devices_lookup() {
    let case = Case::in_memory().unwrap();
    let other = "ffffffff-0000-4000-8000-00000000ffff";
    put(
        &case,
        "devices",
        json!({"record_key": other, "device_id": other, "object_id": DEVICE_OBJECT}),
    );
    put_audit(
        &case,
        "da-1",
        json!([{"Type": "Device", "Id": DEVICE_OBJECT_UPPER}]),
        Some(json!([{"target": "x", "property": "DeviceId", "old": null, "new": DEVICE_UPPER}])),
    );
    events::rebuild(case.conn()).unwrap();
    assert_eq!(
        cell(&case, "directory_audits", "da-1", "device_id").as_deref(),
        Some(DEVICE)
    );
}

#[test]
fn signin_service_event_types_win_over_is_interactive() {
    let case = Case::in_memory().unwrap();
    for (key, event_type, interactive) in [
        ("sp", "service_principal", true),
        ("mi", "managed_identity", true),
        ("int", "interactive", false),
        ("non", "noninteractive", true),
    ] {
        put(
            &case,
            "signins",
            json!({"record_key": key, "event_time": "2026-09-01T10:02:00Z", "event_type": event_type,
                   "is_interactive": interactive}),
        );
    }
    events::rebuild(case.conn()).unwrap();
    for (key, source) in [
        ("sp", "signin_service"),
        ("mi", "signin_service"),
        ("int", "signin_interactive"),
        // is_interactive only decides when event_type is NULL, so a typed non-interactive row stays so.
        ("non", "signin_noninteractive"),
    ] {
        assert_eq!(
            cell(&case, "signins", key, "source").as_deref(),
            Some(source),
            "{key}"
        );
    }
}

#[test]
fn device_prefixed_target_ids_are_normalized() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        "devices",
        json!({"record_key": DEVICE, "device_id": DEVICE, "object_id": DEVICE_OBJECT}),
    );
    put_audit(
        &case,
        "da-prefixed",
        json!([{"Type": "Device", "Id": format!("Device_{DEVICE_OBJECT_UPPER}"), "DisplayName": "LAPTOP-01"}]),
        None,
    );
    events::rebuild(case.conn()).unwrap();
    let some = |x: &str| Some(x.to_string());
    assert_eq!(
        audit_device(&case, "da-prefixed"),
        (some(DEVICE), some(DEVICE_OBJECT), some("LAPTOP-01"))
    );
}

#[test]
fn several_distinct_device_targets_are_ambiguous_but_the_same_device_twice_is_not() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        "devices",
        json!({"record_key": DEVICE, "device_id": DEVICE, "object_id": DEVICE_OBJECT}),
    );
    // Two different devices, even with a DeviceId property and a devices match for one: nothing is assigned.
    put_audit(
        &case,
        "da-two",
        json!([{"Type": "Device", "Id": DEVICE_OBJECT_UPPER, "DisplayName": "LAPTOP-01"},
               {"Type": "Device", "Id": UNKNOWN_OBJECT, "DisplayName": "LAPTOP-02"}]),
        Some(json!([{"target": "x", "property": "DeviceId", "old": null, "new": DEVICE_UPPER}])),
    );
    // Device_<oid> and the bare oid are one device; a user target alongside is irrelevant.
    put_audit(
        &case,
        "da-same",
        json!([{"Type": "User", "Id": "u-1"},
               {"Type": "Device", "Id": format!("Device_{DEVICE_OBJECT_UPPER}"), "DisplayName": "LAPTOP-01"},
               {"Type": "Device", "Id": DEVICE_OBJECT}]),
        None,
    );
    events::rebuild(case.conn()).unwrap();
    let some = |x: &str| Some(x.to_string());
    assert_eq!(audit_device(&case, "da-two"), (None, None, None));
    assert_eq!(
        audit_device(&case, "da-same"),
        (some(DEVICE), some(DEVICE_OBJECT), some("LAPTOP-01"))
    );
}

/// Wall-clock measurement on a case kept by the synthetic perf harness; nothing to time without it:
/// SPARROW_PERF_KEEP=<dir> cargo test -p sparrow-core --release --test events_build rebuild_timing -- --ignored --nocapture
#[test]
#[ignore = "heavy, wall-clock"]
fn rebuild_timing_on_kept_case() {
    let Some(keep) = std::env::var_os("SPARROW_PERF_KEEP") else {
        println!("SPARROW_PERF_KEEP is not set; nothing to time");
        return;
    };
    let case = Case::create_or_open(&std::path::Path::new(&keep).join("case.duckdb")).unwrap();
    let t = std::time::Instant::now();
    let written = events::rebuild(case.conn()).unwrap();
    println!("rebuild {:.2}s, {written} rows", t.elapsed().as_secs_f64());
    println!(
        "ual {} signins {} total {}",
        count(&case, "SELECT count(*) FROM ual_events"),
        count(&case, "SELECT count(*) FROM signins"),
        count(&case, "SELECT count(*) FROM events")
    );
}

/// A Windows Hello for Business key change as the portal audit export has it: the row targets the USER, and the
/// device is only inside the `searchableDeviceKey` value (a JSON list of keys, each with its `deviceId`).
fn put_key_change(case: &Case, key: &str, activity: &str, old: &[&str], new: &[&str]) {
    let keys = |ids: &[&str]| {
        let list: Vec<Value> = ids
            .iter()
            .map(|d| json!({"usage": "NGC", "keyIdentifier": format!("k-{d}"), "deviceId": d}))
            .collect();
        Value::Array(list).to_string()
    };
    put(
        case,
        "directory_audits",
        json!({"record_key": key, "event_time": "2026-09-01T10:04:00Z", "activity": activity,
               "targets": json!([{"type": "User", "id": "11111111-1111-4111-8111-111111111111",
                                  "userPrincipalName": "alice@contoso.example"}]).to_string(),
               "modified_properties": json!([{"target": "alice@contoso.example", "property": "searchableDeviceKey",
                                              "old": keys(old), "new": keys(new)}]).to_string()}),
    );
}

#[test]
fn a_windows_hello_key_change_is_about_the_device_whose_key_came_or_went() {
    let case = Case::in_memory().unwrap();
    let (a, b, c) = (
        "aaaaaaaa-0000-4000-8000-00000000000a",
        "BBBBBBBB-0000-4000-8000-00000000000B",
        "cccccccc-0000-4000-8000-00000000000c",
    );
    // Deleted: the key of b is in the old list, not the new one.
    put_key_change(
        &case,
        "whfb-del",
        "Delete Windows Hello for Business credential",
        &[a, b, c],
        &[a, c],
    );
    // Added: c's key is new.
    put_key_change(
        &case,
        "whfb-add",
        "Add Windows Hello for Business key",
        &[a],
        &[a, c],
    );
    // The only key there is, changed in place.
    put_key_change(&case, "whfb-one", "Update user", &[a], &[a]);
    // Two keys came and went: which device it is about is not known.
    put_key_change(&case, "whfb-two", "Update user", &[a], &[b, c]);
    events::rebuild(case.conn()).unwrap();
    let dev = |k: &str| cell(&case, "directory_audits", k, "device_id");
    assert_eq!(dev("whfb-del").as_deref(), Some(b.to_lowercase().as_str()));
    assert_eq!(dev("whfb-add").as_deref(), Some(c));
    assert_eq!(dev("whfb-one").as_deref(), Some(a));
    assert_eq!(dev("whfb-two"), None);
}

/// A `searchableDeviceKey` change with the old and new values given as written.
fn put_raw_key_change(case: &Case, key: &str, old: &str, new: &str) {
    put(
        case,
        "directory_audits",
        json!({"record_key": key, "event_time": "2026-09-01T10:04:00Z", "activity": "Update user",
               "targets": json!([{"type": "User", "id": "11111111-1111-4111-8111-111111111111"}]).to_string(),
               "modified_properties": json!([{"target": "u", "property": "searchableDeviceKey",
                                              "old": old, "new": new}]).to_string()}),
    );
}

#[test]
fn a_key_change_names_no_device_it_cannot_prove() {
    let case = Case::in_memory().unwrap();
    let a = "aaaaaaaa-0000-4000-8000-00000000000a";
    let b = "bbbbbbbb-0000-4000-8000-00000000000b";
    let zero = "00000000-0000-0000-0000-000000000000";
    let key = |id: &str, dev: &str| json!({"keyIdentifier": id, "deviceId": dev});
    let list = |ks: &[Value]| Value::Array(ks.to_vec()).to_string();
    // A FIDO key (all-zero device id) added next to device a's Hello key: not about a.
    put_raw_key_change(
        &case,
        "fido",
        &list(&[key("k1", a)]),
        &list(&[key("k1", a), key("f1", zero)]),
    );
    // Device a's second key deleted while device b has one too: it is a, whatever else the list holds.
    put_raw_key_change(
        &case,
        "rotate",
        &list(&[key("k1", a), key("k2", a), key("k3", b)]),
        &list(&[key("k1", a), key("k3", b)]),
    );
    // An old value that is not a key list: nothing is proven.
    put_raw_key_change(
        &case,
        "broken",
        "[{\"keyIdentifier\": \"k1\", \"deviceId\"",
        &list(&[key("k1", a)]),
    );
    // Double-encoded, as Graph writes it: still read.
    let quoted = |ks: &[Value]| Value::String(list(ks)).to_string();
    put_raw_key_change(
        &case,
        "quoted",
        &quoted(&[key("k1", a), key("k2", b)]),
        &quoted(&[key("k1", a)]),
    );
    events::rebuild(case.conn()).unwrap();
    let dev = |k: &str| cell(&case, "directory_audits", k, "device_id");
    assert_eq!(dev("fido"), None);
    assert_eq!(dev("rotate").as_deref(), Some(a));
    assert_eq!(dev("broken"), None);
    assert_eq!(dev("quoted").as_deref(), Some(b));
}
