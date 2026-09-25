use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::readers::time::DateOrder;
use std::path::{Path, PathBuf};

fn capture(base: &Path) -> PathBuf {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    root
}

fn json_file(root: &Path, rel: &str, v: &Value) {
    fixtures::write(root, rel, fixtures::ps_json(v).as_bytes());
}

fn ingest(base: &Path, order: Option<DateOrder>) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions {
        date_order: order,
        ..IngestOptions::default()
    };
    let report = ingest_path(&mut case, base, &ParserRegistry::builtin(), &opts).unwrap();
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

const ALICE: &str = "alice@contoso.example";

fn forwarding(target: &str) -> Vec<u8> {
    let v = json!({
        "DisplayName": "Alice", "UserPrincipalName": ALICE, "PrimarySmtpAddress": ALICE,
        "ForwardingSmtpAddress": target, "ForwardingAddress": null,
        "DeliverToMailboxAndForward": false, "WhenChangedUTC": "/Date(1788343200000)/"
    });
    fixtures::utf8_bom(&fixtures::ps51_dates(&fixtures::ps_json(&v)))
}

const MAILBOX_INFO: &str = concat!(
    "\r\n\r\n",
    "Alias                     : alice\r\n",
    "DisplayName               : Alice\r\n",
    "EmailAddresses            : {SMTP:alice@contoso.example, smtp:alice@contoso.onmicrosoft.example,\r\n",
    "                            SIP:alice@contoso.example}\r\n",
    "ExternalDirectoryObjectId : 11111111-1111-4111-8111-111111111111\r\n",
    "Guid                      : 99999999-9999-4999-8999-999999999999\r\n",
    "PrimarySmtpAddress        : Alice@contoso.example\r\n",
    "RecipientType             : UserMailbox\r\n",
    "RecipientTypeDetails      : UserMailbox\r\n",
    "UserPrincipalName         : alice@contoso.example\r\n",
    "\r\n\r\n",
);

const CAS_MAILBOX_INFO: &str = concat!(
    "\r\n\r\n",
    "ActiveSyncEnabled  : True\r\n",
    "DisplayName        : Alice\r\n",
    "EwsEnabled         : True\r\n",
    "ImapEnabled        : False\r\n",
    "MAPIEnabled        : True\r\n",
    "OWAEnabled         : True\r\n",
    "PopEnabled         : True\r\n",
    "PrimarySmtpAddress : alice@contoso.example\r\n",
    "\r\n\r\n",
);

fn auto_reply(start: &str, end: &str) -> String {
    format!(
        concat!(
            "\r\n\r\n",
            "AutoReplyState   : Enabled\r\n",
            "EndTime          : {end}\r\n",
            "ExternalAudience : All\r\n",
            "ExternalMessage  : <html><body>Out of office\r\n",
            "                   until October.</body></html>\r\n",
            "\r\n",
            "InternalMessage  : <html><body>Away\r\n",
            "\r\n",
            "                   back soon</body></html>\r\n",
            "StartTime        : {start}\r\n",
            "MailboxOwnerId   : alice\r\n",
            "\r\n\r\n",
        ),
        start = start,
        end = end
    )
}

#[test]
fn forwarding_report_fills_mailbox_forwarding_and_the_tenant_copy_is_a_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let bytes = forwarding("smtp:x@fabrikam.example");
    fixtures::write(
        &root,
        &format!("{ALICE}/ForwardingReport_alice.json"),
        &bytes,
    );
    fixtures::write(&root, "Tenant/User_ForwardingReport.json", &bytes);
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM mailboxes"), 1);
    assert_eq!(
        text(
            &case,
            "SELECT forwarding_smtp_address || '|' || deliver_and_forward || '|' || epoch(when_changed)::BIGINT FROM mailboxes WHERE record_key = 'alice@contoso.example'"
        ),
        "smtp:x@fabrikam.example|false|1788343200"
    );
    let tenant = row(&report, "Tenant/User_ForwardingReport.json");
    assert_eq!((tenant.records_loaded, tenant.records_duplicate), (0, 1));
}

#[test]
fn cas_and_mailbox_info_fill_different_columns() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        &format!("{ALICE}/ForwardingReport_alice.json"),
        &forwarding("smtp:x@fabrikam.example"),
    );
    fixtures::write(
        &root,
        &format!("{ALICE}/Mailbox_Info_alice.txt"),
        &fixtures::utf16le_bom(MAILBOX_INFO),
    );
    fixtures::write(
        &root,
        &format!("{ALICE}/CAS_Mailbox_Info_alice.txt"),
        &fixtures::utf16le_bom(CAS_MAILBOX_INFO),
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM mailboxes"), 1);
    assert_eq!(
        text(
            &case,
            "SELECT recipient_type || '|' || object_id || '|' || mailbox_guid || '|' || primary_smtp_address || '|' || pop_enabled || '|' || imap_enabled || '|' || display_name || '|' || forwarding_smtp_address FROM mailboxes"
        ),
        "UserMailbox|11111111-1111-4111-8111-111111111111|99999999-9999-4999-8999-999999999999|alice@contoso.example|true|false|Alice|smtp:x@fabrikam.example"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'mailboxes'"
        ),
        3
    );
}

#[test]
fn auto_reply_with_blank_lines_in_the_message_is_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        &format!("{ALICE}/AutoReply_alice.txt"),
        &fixtures::utf16le_bom(&auto_reply("9/24/2026 8:00:00 AM", "9/30/2026 5:00:00 PM")),
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        text(
            &case,
            "SELECT auto_reply_state || '|' || auto_reply_external_audience || '|' || auto_reply_message || '|' || epoch(auto_reply_start)::BIGINT FROM mailboxes"
        ),
        "Enabled|All|<html><body>Away back soon</body></html>|1790236800"
    );
    assert_eq!(
        text(&case, "SELECT auto_reply_external_message FROM mailboxes"),
        "<html><body>Out of office until October.</body></html>"
    );
}

#[test]
fn ambiguous_auto_reply_dates_fail_unless_culture_given() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        &format!("{ALICE}/AutoReply_alice.txt"),
        &fixtures::utf16le_bom(&auto_reply("9/10/2026 8:00:00 AM", "9/11/2026 5:00:00 PM")),
    );
    let rel = format!("{ALICE}/AutoReply_alice.txt");
    let (_case, report) = ingest(dir.path(), None);
    let f = row(&report, &rel);
    assert_eq!(f.status, FileStatus::Error);
    assert!(
        f.warnings.iter().any(|w| w.contains("--culture")),
        "{:?}",
        f.warnings
    );
    let (case, report) = ingest(dir.path(), Some(DateOrder::MonthFirst));
    assert_eq!(row(&report, &rel).status, FileStatus::Parsed);
    assert_eq!(
        count(
            &case,
            "SELECT epoch(auto_reply_start)::BIGINT FROM mailboxes"
        ),
        1_789_027_200
    );
}

const ADMIN_AUDIT_LOG_CONFIG: &str = concat!(
    "\r\n\r\n",
    "AdminAuditLogAgeLimit           : 90.00:00:00\r\n",
    "AdminAuditLogCmdlets            : {*}\r\n",
    "AdminAuditLogEnabled            : True\r\n",
    "AdminAuditLogExcludedCmdlets    : {Set-MailboxAuditBypassAssociation, New-MailboxAuditBypass\r\n",
    "                                  , Set-Foo}\r\n",
    "LogLevel                        : None\r\n",
    "UnifiedAuditLogIngestionEnabled : False\r\n",
    "\r\n\r\n",
);

#[test]
fn admin_audit_and_org_config_fill_audit_config_and_settings() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        "Tenant/AdminAuditLogConfig.txt",
        &fixtures::utf16le_bom(ADMIN_AUDIT_LOG_CONFIG),
    );
    fixtures::write(
        &root,
        "Tenant/OrgConfig.txt",
        b"\r\nAuditDisabled          : True\r\nMailTipsAllTipsEnabled : True\r\nName                   : Contoso\r\n\r\n",
    );
    json_file(
        &root,
        "Tenant/TransportConfig.json",
        &json!({
            "SmtpClientAuthenticationDisabled": true, "ExternalDelayDsnEnabled": false,
            "TransportRuleMinProductVersion": {"Major": 15, "Minor": 0}
        }),
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        text(
            &case,
            "SELECT admin_audit_log_enabled || '|' || unified_audit_log_ingestion_enabled || '|' || audit_disabled || '|' || admin_audit_log_age_limit || '|' || log_level FROM audit_config WHERE record_key = 'organization'"
        ),
        "true|false|true|90.00:00:00|None"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM audit_config"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM tenant_settings"), 12);
    assert_eq!(
        text(
            &case,
            "SELECT value->>'$' FROM tenant_settings WHERE record_key = 'admin_audit_log_config|adminauditlogexcludedcmdlets'"
        ),
        "{Set-MailboxAuditBypassAssociation, New-MailboxAuditBypass , Set-Foo}"
    );
    assert_eq!(
        count(
            &case,
            "SELECT rs.line_start FROM record_sources rs WHERE rs.table_name = 'tenant_settings' AND rs.record_key = 'admin_audit_log_config|unifiedauditlogingestionenabled'"
        ),
        9
    );
    assert_eq!(
        text(
            &case,
            "SELECT value->>'$.Major' FROM tenant_settings WHERE record_key = 'transport_config|transportruleminproductversion'"
        ),
        "15"
    );
    assert_eq!(
        text(
            &case,
            "SELECT CAST(value AS VARCHAR) FROM tenant_settings WHERE record_key = 'transport_config|smtpclientauthenticationdisabled'"
        ),
        "true"
    );
}
