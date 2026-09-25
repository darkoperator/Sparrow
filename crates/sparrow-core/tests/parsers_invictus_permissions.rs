use serde_json::{Map, Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures::{self, csv_line};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileReport, IngestOptions, IngestReport, ingest_path};
use sparrow_core::normalize::fields::Rec;
use sparrow_core::parsers::mailbox_permissions::grants;
use sparrow_core::verify::verify_record;
use std::path::Path;

const ALICE: &str = "alice@contoso.example";
const REL: &str = "Mailbox Permissions/20260910-100500/20260910-100500-MailboxPermissions.csv";
const HEADER: &[&str] = &[
    "UserPrincipalName",
    "DisplayName",
    "RecipientTypeDetails",
    "FullAccessUsers",
    "FullAccessPermissions",
    "SendAsUsers",
    "SendAsPermissions",
    "SendOnBehalfUsers",
    "CalendarUsers",
    "CalendarPermissions",
    "InboxUsers",
    "InboxPermissions",
    "FullAccessCount",
    "SendAsCount",
    "SendOnBehalfCount",
    "CalendarPermissionCount",
    "InboxPermissionCount",
];

fn alice_row() -> Vec<&'static str> {
    vec![
        ALICE,
        "Alice",
        "UserMailbox",
        "Bob (bob@contoso.example); Discovery Management",
        "Bob (bob@contoso.example) - Rights: FullAccess, Deny: False, Inheritance: All | Discovery Management - Rights: FullAccess,ReadPermission, Deny: False, Inheritance: All",
        "Mallory (mallory@fabrikam.example)",
        "Mallory (mallory@fabrikam.example) - Type: Allow, Rights: ExtendedRight, Inheritance: None",
        "Carol (carol@contoso.example)",
        "Bob (bob@contoso.example) - Editor",
        "Bob: Editor",
        "",
        "Mallory: ReadItems",
        "2",
        "1",
        "1",
        "1",
        "1",
    ]
}

fn bob_row() -> Vec<&'static str> {
    vec![
        "bob@contoso.example",
        "Bob",
        "SharedMailbox",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "0",
        "0",
        "0",
        "0",
        "0",
    ]
}

fn map(fields: &[&str]) -> Map<String, Value> {
    HEADER
        .iter()
        .zip(fields)
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect()
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

#[test]
#[allow(clippy::type_complexity)]
fn grants_unpack_every_permission_column() {
    let m = map(&alice_row());
    let g = grants(&Rec::new(&m, true));
    let summary: Vec<(&str, Option<&str>, &str, Vec<String>, Option<bool>)> = g
        .iter()
        .map(|g| {
            (
                g.permission,
                g.folder,
                g.grantee.as_str(),
                g.access_rights.clone(),
                g.deny,
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (
                "full_access",
                None,
                "Bob (bob@contoso.example)",
                vec!["FullAccess".to_string()],
                Some(false)
            ),
            (
                "full_access",
                None,
                "Discovery Management",
                vec!["FullAccess".to_string(), "ReadPermission".to_string()],
                Some(false)
            ),
            (
                "send_as",
                None,
                "Mallory (mallory@fabrikam.example)",
                vec!["ExtendedRight".to_string()],
                Some(false)
            ),
            (
                "send_on_behalf",
                None,
                "Carol (carol@contoso.example)",
                vec![],
                None
            ),
            (
                "folder",
                Some("calendar"),
                "Bob (bob@contoso.example)",
                vec!["Editor".to_string()],
                None
            ),
            (
                "folder",
                Some("inbox"),
                "Mallory",
                vec!["ReadItems".to_string()],
                None
            ),
        ]
    );
    assert_eq!(g[2].inheritance.as_deref(), Some("None"));
    assert!(g.iter().all(|g| !g.unparsed));
    assert!(grants(&Rec::new(&map(&bob_row()), true)).is_empty());
}

#[test]
fn deny_entries_and_unmatched_text_are_kept() {
    let mut fields = bob_row();
    fields[4] = "Eve (eve@fabrikam.example) - Rights: FullAccess, Deny: True, Inheritance: All | garbage entry";
    fields[6] = "Eve (eve@fabrikam.example) - Type: Deny, Rights: ExtendedRight, Inheritance: None";
    let m = map(&fields);
    let g = grants(&Rec::new(&m, true));
    assert_eq!(g[0].deny, Some(true));
    assert_eq!(g[1].grantee, "garbage entry");
    assert!(g[1].unparsed);
    assert!(g[1].access_rights.is_empty());
    assert_eq!(g[2].deny, Some(true));
}

#[test]
fn permissions_file_loads_grants_and_mailboxes() {
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "{}{}{}",
        csv_line(HEADER),
        csv_line(&alice_row()),
        csv_line(&bob_row())
    );
    fixtures::write(&dir.path().join("OUT"), REL, body.as_bytes());
    let (case, report) = ingest(dir.path());
    let f = row(&report, REL);
    assert_eq!(f.artifact_id.as_deref(), Some("inv.mailbox_permissions"));
    assert_eq!(f.records_error, 0);
    assert_eq!(count(&case, "SELECT count(*) FROM mailbox_permissions"), 6);
    assert_eq!(count(&case, "SELECT count(*) FROM mailboxes"), 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mailbox_permissions
             WHERE record_key = 'alice@contoso.example|send_as||mallory (mallory@fabrikam.example)'
               AND grantee_upn = 'mallory@fabrikam.example' AND permission = 'send_as'
               AND NOT deny AND inheritance = 'None' AND mailbox_display_name = 'Alice'"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mailbox_permissions
             WHERE grantee = 'Discovery Management' AND grantee_upn IS NULL
               AND access_rights = ['FullAccess', 'ReadPermission']"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mailbox_permissions WHERE permission = 'folder' AND folder = 'calendar'
               AND grantee_upn = 'bob@contoso.example' AND access_rights = ['Editor']"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mailboxes WHERE record_key = 'bob@contoso.example' AND recipient_type = 'SharedMailbox'"
        ),
        1
    );
    assert!(
        verify_record(
            &case,
            "mailbox_permissions",
            "alice@contoso.example|send_on_behalf||carol (carol@contoso.example)",
            None
        )
        .unwrap()
        .ok
    );
}

#[test]
fn unparsed_entries_warn() {
    let dir = tempfile::tempdir().unwrap();
    let mut fields = bob_row();
    fields[4] = "garbage entry";
    let body = format!("{}{}", csv_line(HEADER), csv_line(&fields));
    fixtures::write(&dir.path().join("OUT"), REL, body.as_bytes());
    let (case, report) = ingest(dir.path());
    assert!(
        row(&report, REL)
            .warnings
            .iter()
            .any(|w| w.contains("did not match")),
        "{:?}",
        row(&report, REL).warnings
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mailbox_permissions WHERE grantee = 'garbage entry' AND access_rights IS NULL"
        ),
        1
    );
}
