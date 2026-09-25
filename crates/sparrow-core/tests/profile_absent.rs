//! Task 10: `state_absent_in_newer` - state rows a newer capture of the same artifact, for the
//! same subject and tenant, no longer holds. Latest-wins (Phase 2b) never deletes, so a removed
//! inbox rule otherwise still reads as current.

use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::fixtures::state::{ALICE, BOB, hawk4_state_tree_at};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{FileStatus, IngestOptions, ingest_path};
use sparrow_core::profile::{ProfileOptions, refresh};
use std::path::Path;

const OLD_STAMP: &str = "20260910_090000";
const NEW_STAMP: &str = "20260920_090000";
const FORWARDING: &str = "smtp:x@fabrikam.example";

fn ingest(case: &mut Case, path: &Path) {
    let report = ingest_path(
        case,
        path,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// A Get-InboxRule object shaped like `fixtures::state`'s private helper of the same name.
fn inbox_rule(owner: &str, identity: u64, name: &str) -> Value {
    json!({
        "Description": "desc", "Enabled": true, "Identity": format!("{owner}\\{identity}"),
        "InError": false, "Name": name, "Priority": 1, "RuleIdentity": identity,
        "BodyContainsWords": [], "From": null, "HasAttachment": false, "SubjectContainsWords": [],
        "SubjectOrBodyContainsWords": [], "CopyToFolder": null, "DeleteMessage": false,
        "ForwardAsAttachmentTo": null, "ForwardTo": null, "MarkAsRead": false, "MoveToFolder": null,
        "RedirectTo": null, "SoftDeleteMessage": false, "StopProcessingRules": false,
        "MailboxOwnerId": owner
    })
}

fn write_rules(root: &Path, subject: &str, file_stem: &str, rules: &[Value]) {
    fixtures::write(
        root,
        &format!("{subject}/InboxRules_{file_stem}.json"),
        &fixtures::utf8_bom(&fixtures::ps_json(&json!(rules))),
    );
}

fn collection_id_for(case: &Case, stamp: &str) -> i64 {
    case.conn()
        .query_row(
            &format!("SELECT collection_id FROM collections WHERE root_path LIKE '%{stamp}'"),
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// Older capture, then a newer one whose InboxRules_alice.json drops the "Newsletters" rule
/// (identity 2222) but keeps the "." rule (identity 1111). Ingested old-then-new.
fn ingest_rule_removed(case: &mut Case) -> (String, String) {
    let old_dir = tempfile::tempdir().unwrap();
    let new_dir = tempfile::tempdir().unwrap();
    let old_root = hawk4_state_tree_at(old_dir.path(), OLD_STAMP, FORWARDING);
    let new_root = hawk4_state_tree_at(new_dir.path(), NEW_STAMP, FORWARDING);
    write_rules(&new_root, ALICE, "alice", &[inbox_rule("alice", 1111, ".")]);

    ingest(case, &old_root);
    let kept_key = text(case, "SELECT record_key FROM inbox_rules WHERE name = '.'");
    let removed_key = text(
        case,
        "SELECT record_key FROM inbox_rules WHERE name = 'Newsletters'",
    );
    ingest(case, &new_root);
    refresh(case, &ProfileOptions::default()).unwrap();
    (kept_key, removed_key)
}

#[test]
fn rule_removed_in_the_newer_capture_is_listed() {
    let mut case = Case::in_memory().unwrap();
    let (kept_key, removed_key) = ingest_rule_removed(&mut case);

    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{removed_key}'"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{kept_key}'"
            )
        ),
        0
    );

    let absent_from_at: i64 = case
        .conn()
        .query_row(
            &format!(
                "SELECT epoch(absent_from_at)::BIGINT FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{removed_key}'"
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();
    let new_collected_at: i64 = case
        .conn()
        .query_row(
            &format!(
                "SELECT epoch(collected_at)::BIGINT FROM collections WHERE collection_id = {}",
                collection_id_for(&case, NEW_STAMP)
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(absent_from_at, new_collected_at);
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{removed_key}'
                   AND absent_from_collection_id = {}",
                collection_id_for(&case, NEW_STAMP)
            )
        ),
        1
    );
}

#[test]
fn identical_newer_file_lists_nothing() {
    let old_dir = tempfile::tempdir().unwrap();
    let new_dir = tempfile::tempdir().unwrap();
    let old_root = hawk4_state_tree_at(old_dir.path(), OLD_STAMP, FORWARDING);
    let new_root = hawk4_state_tree_at(new_dir.path(), NEW_STAMP, FORWARDING);

    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, &old_root);
    let report = ingest_path(
        &mut case,
        &new_root,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert!(!report.has_errors(), "{report:#?}");
    let rules_file = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .find(|f| f.rel_path == format!("{ALICE}/InboxRules_alice.json"))
        .unwrap_or_else(|| panic!("no report row for InboxRules_alice.json"));
    assert_eq!(rules_file.status, FileStatus::DuplicateFile);

    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        count(&case, "SELECT count(*) FROM state_absent_in_newer"),
        0
    );
}

#[test]
fn a_user_missing_from_the_newer_capture_entirely_is_not_listed() {
    let old_dir = tempfile::tempdir().unwrap();
    let new_dir = tempfile::tempdir().unwrap();
    let old_root = hawk4_state_tree_at(old_dir.path(), OLD_STAMP, FORWARDING);
    write_rules(&old_root, BOB, "bob", &[inbox_rule("bob", 3333, "Move")]);
    let new_root = hawk4_state_tree_at(new_dir.path(), NEW_STAMP, FORWARDING);
    // No InboxRules file written for bob in the newer capture: bob was not collected at all.

    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, &old_root);
    ingest(&mut case, &new_root);
    refresh(&mut case, &ProfileOptions::default()).unwrap();

    assert!(
        count(
            &case,
            "SELECT count(*) FROM inbox_rules WHERE mailbox_upn = 'bob@contoso.example'"
        ) > 0
    );
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM state_absent_in_newer WHERE subject = '{BOB}'")
        ),
        0
    );
}

#[test]
fn order_of_ingest_does_not_matter() {
    let old_dir = tempfile::tempdir().unwrap();
    let new_dir = tempfile::tempdir().unwrap();
    let old_root = hawk4_state_tree_at(old_dir.path(), OLD_STAMP, FORWARDING);
    let new_root = hawk4_state_tree_at(new_dir.path(), NEW_STAMP, FORWARDING);
    write_rules(&new_root, ALICE, "alice", &[inbox_rule("alice", 1111, ".")]);

    // Ingest newer capture first, then older - same in-order result (test 1) either way.
    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, &new_root);
    ingest(&mut case, &old_root);
    let kept_key = text(&case, "SELECT record_key FROM inbox_rules WHERE name = '.'");
    let removed_key = text(
        &case,
        "SELECT record_key FROM inbox_rules WHERE name = 'Newsletters'",
    );
    refresh(&mut case, &ProfileOptions::default()).unwrap();

    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{removed_key}'"
            )
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{kept_key}'"
            )
        ),
        0
    );
}
