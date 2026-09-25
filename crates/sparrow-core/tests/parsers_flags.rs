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

const ALICE_ID: &str = "11111111-1111-4111-8111-111111111111";
const APP: &str = "33333333-3333-4333-8333-333333333333";
const GRAPH: &str = "44444444-4444-4444-8444-444444444444";

#[test]
fn investigate_files_link_to_the_rows_their_parsers_create() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    let rule = json!({"Name": "x", "RuleIdentity": 1111, "MailboxOwnerId": "alice",
        "ForwardTo": ["\"x\" [SMTP:x@fabrikam.example]"], "Identity": "alice\\1111"});
    json_file(
        &root,
        "alice@contoso.example/InboxRules_alice.json",
        &json!([rule.clone(), {"Name": "y", "RuleIdentity": 2222, "MailboxOwnerId": "alice"}]),
    );
    json_file(
        &root,
        "alice@contoso.example/_Investigate_InboxRules_alice.json",
        &rule,
    );
    let grant = json!({"PermissionType": "Delegated", "ClientObjectId": APP, "ResourceObjectId": GRAPH,
        "Permission": "Mail.Read", "ConsentType": "Principal", "PrincipalObjectId": ALICE_ID,
        "ConsentGrantRiskCategory": "High Risk"});
    json_file(&root, "Tenant/Consent_Grants.json", &json!([grant.clone()]));
    json_file(&root, "Tenant/_Investigate_Consent_Grants.json", &grant);
    let risky = json!({"Id": ALICE_ID, "UserPrincipalName": "alice@contoso.example",
        "RiskLevel": "high", "RiskState": "atRisk"});
    json_file(&root, "Tenant/RiskyUsers.json", &risky);
    json_file(&root, "Tenant/_Investigate_Risky_Users.json", &risky);
    let raw = fixtures::ual::raw_record(
        "ExchangeAdmin",
        "2026-09-01T10:00:05",
        "New-InboxRule",
        &fixtures::ual::rule(),
    );
    json_file(
        &root,
        "Tenant/Admin_Inbox_Rules_Creation.json",
        &json!([raw.clone()]),
    );
    json_file(
        &root,
        "Tenant/_Investigate_Admin_Inbox_Rules_Creation.json",
        &raw,
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM collector_flags"), 4);
    for table in ["inbox_rules", "oauth_grants", "risky_users"] {
        assert_eq!(
            count(
                &case,
                &format!(
                    "SELECT count(*) FROM collector_flags f JOIN {table} t ON t.record_key = f.linked_key WHERE f.linked_table = '{table}'"
                )
            ),
            1,
            "{table}"
        );
    }
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_flags f JOIN ual_events e ON CAST(e.record_id AS VARCHAR) = f.linked_key WHERE f.linked_table = 'ual_events'"
        ),
        1
    );
    assert_eq!(
        text(
            &case,
            "SELECT subject || '|' || flag_type FROM collector_flags WHERE linked_table = 'inbox_rules'"
        ),
        "alice@contoso.example|inbox_rule"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_flags f JOIN source_files s ON s.file_id = f.file_id WHERE s.rel_path LIKE '%_Investigate_%'"
        ),
        4
    );
}

#[test]
fn hawk3_admin_audit_flags_keep_a_null_link() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        "Tenant/_Investigate_New_InboxRules.txt",
        concat!(
            "\r\n\r\n",
            "ObjectModified   : contoso.example/alice/Rule1\r\n",
            "CmdletName       : New-InboxRule\r\n",
            "CmdletParameters : {Name, ForwardTo}\r\n",
            "Caller           : admin@contoso.example\r\n",
            "RunDate          : 9/2/2026 8:00:00 AM\r\n",
            "\r\n",
            "ObjectModified   : contoso.example/bob/Rule2\r\n",
            "CmdletName       : New-InboxRule\r\n",
            "CmdletParameters : {Name, DeleteMessage}\r\n",
            "Caller           : admin@contoso.example\r\n",
            "RunDate          : 9/2/2026 8:05:00 AM\r\n",
            "\r\n",
        )
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_flags WHERE flag_type = 'admin_inbox_rule_change' AND linked_table = 'admin_audit_events' AND linked_key IS NULL"
        ),
        2
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_flags WHERE raw->>'$.CmdletName' = 'New-InboxRule'"
        ),
        2
    );
}

#[test]
fn investigate_txt_hawk4_lines() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        "_Investigate.txt",
        concat!(
            "[2026-09-10 14:20:00Z] - [INVESTIGATE] - Found 1 inbox rules requiring investigation for alice@contoso.example\r\n",
            "[2026-09-10 14:20:01Z] - [INVESTIGATE] - Additional Information: C:\\Hawk\\Hawk_Contoso\\alice@contoso.example\\_Investigate_InboxRules_alice.json\r\n",
        )
        .as_bytes(),
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(
        count(
            &case,
            "SELECT epoch(flag_time)::BIGINT FROM collector_flags WHERE flag_type = 'investigate_note'"
        ),
        1_789_050_000
    );
    assert_eq!(
        text(
            &case,
            "SELECT linked_table || '|' || linked_key FROM collector_flags WHERE flag_type = 'investigate_file_reference'"
        ),
        "source_files|alice@contoso.example/_Investigate_InboxRules_alice.json"
    );
}

#[test]
fn investigate_txt_hawk3_lines_inherit_time_and_tag() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        "_Investigate.txt",
        &fixtures::utf16le_bom(concat!(
            "[9/24/2026 2:20:00 PM] - ## Impersonation ## - Found accounts with ApplicationImpersonation rights\r\n",
            "Additional Information: C:\\Hawk\\cap\\Tenant\\_Investigate_Impersonation_Rights.csv\r\n",
        )),
    );
    let (case, report) = ingest(dir.path(), None);
    assert!(!report.has_errors(), "{report:#?}");
    assert_eq!(count(&case, "SELECT count(*) FROM collector_flags"), 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_flags WHERE category = 'Impersonation' AND epoch(flag_time)::BIGINT = 1790259600"
        ),
        2
    );
    assert_eq!(
        text(
            &case,
            "SELECT linked_key FROM collector_flags WHERE flag_type = 'investigate_file_reference'"
        ),
        "Tenant/_Investigate_Impersonation_Rights.csv"
    );
}

#[test]
fn ambiguous_investigate_times_are_null_with_warning() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        "_Investigate.txt",
        b"[9/10/2026 2:20:00 PM] - ## InboxRules ## - Found suspicious inbox rules\r\n",
    );
    let (case, report) = ingest(dir.path(), None);
    let f = row(&report, "_Investigate.txt");
    assert_eq!((f.status, f.records_loaded), (FileStatus::Parsed, 1));
    assert!(
        f.warnings.iter().any(|w| w.contains("--culture")),
        "{:?}",
        f.warnings
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM collector_flags WHERE flag_time IS NULL"
        ),
        1
    );
}

#[test]
fn unknown_investigate_file_is_an_unlinked_other_flag() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    json_file(
        &root,
        "Tenant/_Investigate_Something_New.json",
        &json!({"Name": "x", "Value": 1}),
    );
    let (case, report) = ingest(dir.path(), None);
    assert_eq!(
        row(&report, "Tenant/_Investigate_Something_New.json").status,
        FileStatus::Parsed
    );
    assert_eq!(count(&case, "SELECT count(*) FROM collector_flags"), 1);
    assert_eq!(
        text(
            &case,
            "SELECT flag_type || '|' || (linked_table IS NULL) || '|' || (linked_key IS NULL) FROM collector_flags"
        ),
        "other|true|true"
    );
}
