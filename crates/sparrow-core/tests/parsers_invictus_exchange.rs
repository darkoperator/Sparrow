use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use std::path::Path;

const ALICE: &str = "alice@contoso.example";
const BOB: &str = "bob@contoso.example";
const TRACE_1: &str = "0e0e0e0e-0000-4000-8000-000000000011";
const TRACE_2: &str = "0e0e0e0e-0000-4000-8000-000000000012";
const TRACE_HEADER: &[&str] = &[
    "MessageTraceId",
    "MessageId",
    "Received",
    "SenderAddress",
    "RecipientAddress",
    "FromIP",
    "ToIP",
    "Subject",
    "Status",
    "Size",
];
const STATUS_HEADER: &[&str] = &[
    "UserPrincipalName",
    "DisplayName",
    "RecipientTypeDetails",
    "AuditEnabled",
    "AuditBypassEnabled",
    "DefaultAuditSet",
    "OwnerAuditActions",
    "OwnerAuditActionsCount",
    "DelegateAuditActions",
    "DelegateAuditActionsCount",
    "AdminAuditActions",
    "AdminAuditActionsCount",
    "EffectiveAuditState",
];
const OWNER: &str = "ApplyRecord, Create, HardDelete, MailItemsAccessed, MoveToDeletedItems, Send, SoftDelete, Update, UpdateCalendarDelegation, UpdateFolderPermissions, UpdateInboxRules";

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

fn trace_file() -> String {
    format!(
        "{}{}{}",
        csv_line(TRACE_HEADER),
        csv_line(&[
            TRACE_1,
            "<m1@contoso.example>",
            "9/1/2026 10:20:00 AM",
            "mallory@fabrikam.example",
            ALICE,
            "198.51.100.7",
            "",
            "Updated bank details",
            "Delivered",
            "2048"
        ]),
        csv_line(&[
            TRACE_2,
            "<m2@contoso.example>",
            "8/15/2026 2:00:00 PM",
            ALICE,
            "carol@fabrikam.example",
            "",
            "",
            "Re: invoice",
            "Failed",
            "64194"
        ])
    )
}

fn status_row(upn: &str, bypass: &str, state: &str) -> String {
    csv_line(&[
        upn,
        "Name",
        "UserMailbox",
        "True",
        bypass,
        "Admin, Delegate, Owner",
        OWNER,
        "11",
        "ApplyRecord, Create",
        "2",
        "ApplyRecord, Create, Send",
        "3",
        state,
    ])
}

#[test]
fn message_trace_exports_load_once() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let first = "MessageTrace/20260910-100600/20260910-100600-MessageTrace.csv";
    let again = "MessageTrace/20260910-110600/20260910-110600-MessageTrace.csv";
    let mtl = "MessageTrace/20260910-120600/alice@contoso.example-MTL.csv";
    fixtures::write(&out, first, trace_file().as_bytes());
    fixtures::write(&out, again, trace_file().as_bytes());
    // The per-user MTL file repeats the first message.
    let mtl_body = format!(
        "{}{}",
        csv_line(TRACE_HEADER),
        csv_line(&[
            TRACE_1,
            "<m1@contoso.example>",
            "9/1/2026 10:20:00 AM",
            "mallory@fabrikam.example",
            ALICE,
            "198.51.100.7",
            "",
            "Updated bank details",
            "Delivered",
            "2048"
        ])
    );
    fixtures::write(&out, mtl, mtl_body.as_bytes());
    let (case, report) = ingest(dir.path());
    assert_eq!(
        row(&report, first).artifact_id.as_deref(),
        Some("inv.message_trace")
    );
    assert_eq!(row(&report, first).records_loaded, 2);
    assert_eq!(row(&report, again).status, FileStatus::DuplicateFile);
    assert_eq!(
        row(&report, mtl).artifact_id.as_deref(),
        Some("inv.message_trace")
    );
    assert_eq!(row(&report, mtl).records_duplicate, 1);
    assert_eq!(count(&case, "SELECT count(*) FROM message_trace"), 2);
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT epoch(received)::BIGINT FROM message_trace WHERE message_trace_id = '{TRACE_1}'"
            )
        ),
        1_788_258_000
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM message_trace WHERE message_trace_id = '{TRACE_2}'
                   AND recipient = 'carol@fabrikam.example' AND from_ip IS NULL AND size_bytes = 64194"
            )
        ),
        1
    );
}

#[test]
fn later_audit_status_run_wins_within_the_collection() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let early = "Audit Status/20260910-100400/20260910-100400-MailboxAuditStatus.csv";
    let late = "Audit Status/20260910-110400/20260910-110400-MailboxAuditStatus.csv";
    fixtures::write(
        &out,
        early,
        format!(
            "{}{}{}",
            csv_line(STATUS_HEADER),
            status_row(ALICE, "False", "Enabled (Organization Policy)"),
            status_row(BOB, "False", "Enabled (Organization Policy)")
        )
        .as_bytes(),
    );
    fixtures::write(
        &out,
        late,
        format!(
            "{}{}{}",
            csv_line(STATUS_HEADER),
            status_row(ALICE, "False", "Enabled (Organization Policy)"),
            status_row(BOB, "True", "Bypassed")
        )
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert_eq!(
        row(&report, early).artifact_id.as_deref(),
        Some("inv.audit_status")
    );
    assert_eq!(row(&report, late).status, FileStatus::Parsed);
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM mailboxes WHERE record_key = '{BOB}'
                   AND audit_bypass_enabled AND effective_audit_state = 'Bypassed'"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM mailboxes WHERE record_key = '{ALICE}' AND audit_enabled
                   AND NOT audit_bypass_enabled
                   AND default_audit_set = ['Admin', 'Delegate', 'Owner']
                   AND list_contains(audit_owner, 'MailItemsAccessed') AND len(audit_owner) = 11
                   AND audit_delegate = ['ApplyRecord', 'Create']
                   AND recipient_type = 'UserMailbox'"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM audit_config WHERE record_key = 'organization' AND audit_disabled = false"
        ),
        1
    );
}

#[test]
fn conflicting_effective_states_leave_the_org_setting_unset() {
    let dir = tempfile::tempdir().unwrap();
    let rel = "Audit Status/20260910-100400/20260910-100400-MailboxAuditStatus.csv";
    fixtures::write(
        &dir.path().join("OUT"),
        rel,
        format!(
            "{}{}{}",
            csv_line(STATUS_HEADER),
            status_row(ALICE, "False", "Enabled (Organization Policy)"),
            status_row(BOB, "False", "Disabled")
        )
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert!(
        row(&report, rel)
            .warnings
            .iter()
            .any(|w| w.contains("EffectiveAuditState")),
        "{:?}",
        row(&report, rel).warnings
    );
    assert_eq!(count(&case, "SELECT count(*) FROM audit_config"), 0);
    assert_eq!(count(&case, "SELECT count(*) FROM mailboxes"), 2);
}

#[test]
fn security_defaults_fill_settings_and_audit_config() {
    let dir = tempfile::tempdir().unwrap();
    let rel = "Licenses/20260910-101000/20260910-101000-EntraSecurityDefaults.csv";
    fixtures::write(
        &dir.path().join("OUT"),
        rel,
        format!(
            "{}{}",
            csv_line(&[
                "SecurityDefaultsEnabled",
                "HasPremiumLicense",
                "RecommendedState",
                "AlignedWithRecommendations",
                "CheckDate"
            ]),
            csv_line(&["No", "No", "Enabled", "No", "2026-09-10 10:10:00"])
        )
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path());
    assert_eq!(
        row(&report, rel).artifact_id.as_deref(),
        Some("inv.licenses.security_defaults")
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM tenant_settings WHERE source = 'entra_security_defaults'"
        ),
        4
    );
    assert_eq!(
        text(
            &case,
            "SELECT value->>'$' FROM tenant_settings WHERE record_key = 'entra_security_defaults|haspremiumlicense'"
        ),
        "No"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM audit_config WHERE record_key = 'organization' AND security_defaults_enabled = false"
        ),
        1
    );
}
