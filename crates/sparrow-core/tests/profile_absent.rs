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

/// Like `inbox_rule`, but with no `MailboxOwnerId`: the loader then falls back to the folder
/// subject for the mailbox, so byte-identical rule content placed under two different subject
/// folders lands on two different record_keys despite sharing one sha256.
fn inbox_rule_no_owner(identity: u64, name: &str) -> Value {
    json!({
        "Description": "desc", "Enabled": true, "Identity": format!("x\\{identity}"),
        "InError": false, "Name": name, "Priority": 1, "RuleIdentity": identity,
        "BodyContainsWords": [], "From": null, "HasAttachment": false, "SubjectContainsWords": [],
        "SubjectOrBodyContainsWords": [], "CopyToFolder": null, "DeleteMessage": false,
        "ForwardAsAttachmentTo": null, "ForwardTo": null, "MarkAsRead": false, "MoveToFolder": null,
        "RedirectTo": null, "SoftDeleteMessage": false, "StopProcessingRules": false
    })
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

/// Fix round 1, item 1: the duplicate_file twin join must be scoped by artifact_type and
/// subject, not sha256 alone. Alice's and bob's rule files coincidentally share one sha256
/// (identical bytes; each rule has no `MailboxOwnerId`, so the mailbox - and so the record_key -
/// comes from its own folder subject instead). Alice's newer-capture file is a genuine
/// duplicate_file of her own older file; bob's rule is genuinely gone in the newer capture. An
/// unscoped twin join would let alice's duplicate_file "borrow" bob's row (same sha256) and,
/// via `last_any`, wrongly advance bob's last-seen time to alice's, hiding bob's real removal.
#[test]
fn duplicate_twin_join_is_scoped_by_artifact_and_subject() {
    let old_dir = tempfile::tempdir().unwrap();
    let new_dir = tempfile::tempdir().unwrap();
    let old_root = hawk4_state_tree_at(old_dir.path(), OLD_STAMP, FORWARDING);
    let new_root = hawk4_state_tree_at(new_dir.path(), NEW_STAMP, FORWARDING);

    let shared = [inbox_rule_no_owner(9999, "Shared")];
    write_rules(&old_root, ALICE, "alice", &shared);
    write_rules(&old_root, BOB, "bob", &shared);
    write_rules(&new_root, ALICE, "alice", &shared);
    write_rules(&new_root, BOB, "bob", &[]);

    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, &old_root);
    let old_id = collection_id_for(&case, OLD_STAMP);
    // Repro precondition: two unrelated parsed files (different subjects) really do share one
    // sha256.
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(DISTINCT sha256) FROM source_files
                 WHERE collection_id = {old_id}
                   AND rel_path IN ('{ALICE}/InboxRules_alice.json', '{BOB}/InboxRules_bob.json')"
            )
        ),
        1
    );
    let bob_key = text(
        &case,
        "SELECT record_key FROM inbox_rules WHERE mailbox_upn = 'bob@contoso.example'",
    );

    ingest(&mut case, &new_root);
    let new_id = collection_id_for(&case, NEW_STAMP);
    assert_eq!(
        text(
            &case,
            &format!(
                "SELECT CAST(status AS VARCHAR) FROM source_files
                 WHERE collection_id = {new_id} AND rel_path = '{ALICE}/InboxRules_alice.json'"
            )
        ),
        "duplicate_file"
    );

    refresh(&mut case, &ProfileOptions::default()).unwrap();
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{bob_key}'"
            )
        ),
        1
    );
}

/// Fix round 1, item 2: "newer" must fall back to collection_id when collected_at is NULL on
/// either side (the loader's own rule in ingest/state.rs update_existing), not go silent.
#[test]
fn null_collected_at_falls_back_to_collection_id() {
    let mut case = Case::in_memory().unwrap();
    let (_kept_key, removed_key) = ingest_rule_removed(&mut case);

    case.conn()
        .execute("UPDATE collections SET collected_at = NULL", [])
        .unwrap();

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
                 WHERE table_name = 'inbox_rules' AND record_key = '{removed_key}'
                   AND absent_from_collection_id = {}
                   AND absent_from_at IS NULL",
                collection_id_for(&case, NEW_STAMP)
            )
        ),
        1
    );
}

/// Fix round 2: `sparrow_collection_is_newer` must fall back to collection_id ENTIRELY when
/// either side's collected_at is unknown - never let a known collected_at outrank an unknown one
/// just because it "looks newer". The older (lower collection_id) capture keeps its real
/// collected_at; the newer (higher collection_id) capture's is nulled. Per the exact rule
/// (ingest/state.rs update_existing), comparing the newer capture ("n", collected_at NULL) to
/// the last-seen older capture ("m", collected_at known) is not-both-known, so it falls back to
/// collection_id: the newer capture's collection_id is still greater, so it is still newer, and
/// the removal must still be detected. THIS is the ordering that actually distinguishes the fix
/// from round 1's coalesce(collected_at, -infinity) tie-break: coalescing "n"'s NULL to
/// -infinity makes its tuple compare as older than "m"'s known timestamp regardless of
/// collection_id, so round 1 wrongly concluded "n" was not newer and the removal went
/// undetected (confirmed by reverting to round 1's SQL: this test fails, `left: 0, right: 1`).
/// The companion test right after this one exercises the reverse ordering, which round 1 happens
/// to get right too - see its docstring for why that one does not distinguish the two approaches.
#[test]
fn mixed_null_collected_at_older_known_newer_unknown_still_falls_back_to_collection_id() {
    let mut case = Case::in_memory().unwrap();
    let (_kept_key, removed_key) = ingest_rule_removed(&mut case);
    let new_id = collection_id_for(&case, NEW_STAMP);

    case.conn()
        .execute(
            &format!("UPDATE collections SET collected_at = NULL WHERE collection_id = {new_id}"),
            [],
        )
        .unwrap();

    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{removed_key}'
                   AND absent_from_collection_id = {new_id} AND absent_from_at IS NULL"
            )
        ),
        1
    );
}

/// Fix round 2, the "vice versa" ordering the review asked for, reproduced through real ingest.
/// The older (lower collection_id) capture's collected_at is nulled instead; the newer (higher
/// collection_id) capture keeps its real, later collected_at. Both the exact rule and round 1's
/// coalesce(collected_at, -infinity) approach agree the newer capture is still newer here
/// (coalescing the OLDER capture's NULL to -infinity still leaves it "older" than any real
/// timestamp, so round 1 reaches the right answer too) - this ordering does NOT distinguish the
/// two approaches (it passes even against round 1's SQL). See the test above for the ordering
/// that does distinguish them.
#[test]
fn mixed_null_collected_at_older_unknown_newer_known_still_detects_removal() {
    let mut case = Case::in_memory().unwrap();
    let (_kept_key, removed_key) = ingest_rule_removed(&mut case);
    let old_id = collection_id_for(&case, OLD_STAMP);
    let new_id = collection_id_for(&case, NEW_STAMP);
    let new_collected_at: i64 = case
        .conn()
        .query_row(
            &format!(
                "SELECT epoch(collected_at)::BIGINT FROM collections WHERE collection_id = {new_id}"
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();

    case.conn()
        .execute(
            &format!("UPDATE collections SET collected_at = NULL WHERE collection_id = {old_id}"),
            [],
        )
        .unwrap();

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
    assert_eq!(absent_from_at, new_collected_at);
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM state_absent_in_newer
                 WHERE table_name = 'inbox_rules' AND record_key = '{removed_key}'
                   AND absent_from_collection_id = {new_id}"
            )
        ),
        1
    );
}

/// Fix round 1, item 3: subject must be compared case-insensitively (folder names carry
/// whatever casing the collector wrote to disk). Only the newer capture's stored subject is
/// recased here - the record content is untouched - to isolate the join's casing behaviour.
#[test]
fn subject_casing_differs_but_removal_is_still_detected() {
    let mut case = Case::in_memory().unwrap();
    let (_kept_key, removed_key) = ingest_rule_removed(&mut case);

    case.conn()
        .execute(
            &format!(
                "UPDATE source_files SET subject = 'Alice@Contoso.EXAMPLE'
                 WHERE collection_id = {} AND rel_path = '{ALICE}/InboxRules_alice.json'",
                collection_id_for(&case, NEW_STAMP)
            ),
            [],
        )
        .unwrap();

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
}

/// Fix round 3: three collections sighting the same record form the cycle the review
/// demonstrated with duckdb directly - collection 1 (collected_at known, "big"), collection 2
/// (collected_at unknown), collection 3 (collected_at known, "small") - where 1 beats 3 by
/// collected_at, 3 beats 2 by collection_id (2's collected_at is unknown), and 2 beats 1 by
/// collection_id (2's collected_at is unknown) too. Realistic trigger: two known-time captures
/// ingested out of time order (collection 1's Sept 20 capture ingested BEFORE collection 3's
/// Sept 5 one) plus one with an unknown collected_at in between. Round 2's "keep the row nothing
/// beats" (NOT EXISTS) finds no winner in a cycle like this - every member is beaten by exactly
/// one other - so it drops the whole `seen` group, and with it the record, rather than reporting
/// a removal. Collections 1-3 all reproduce the same InboxRules_alice.json byte-for-byte (2 and
/// 3 are duplicate_file, borrowed via the twin join), so both rules are sighted identically by
/// all three; a fourth, unambiguously later capture (Sept 30, ingested last) then genuinely
/// drops the "Newsletters" rule. Asserts the removal is still listed - the record must not
/// vanish just because its `seen` group cycles - and that the surviving "." rule is not.
#[test]
fn three_collection_cycle_in_seen_does_not_drop_the_record() {
    const STAMP_1: &str = "20260920_090000"; // Sept 20 - known, "big" collected_at
    const STAMP_2: &str = "20260912_090000"; // collected_at nulled below - the unknown vertex
    const STAMP_3: &str = "20260905_090000"; // Sept 5 - known, "small" collected_at
    const STAMP_4: &str = "20260930_090000"; // unambiguously later than 1, 2 and 3 - the removal

    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();
    let dir3 = tempfile::tempdir().unwrap();
    let dir4 = tempfile::tempdir().unwrap();
    let root1 = hawk4_state_tree_at(dir1.path(), STAMP_1, FORWARDING);
    let root2 = hawk4_state_tree_at(dir2.path(), STAMP_2, FORWARDING);
    let root3 = hawk4_state_tree_at(dir3.path(), STAMP_3, FORWARDING);
    let root4 = hawk4_state_tree_at(dir4.path(), STAMP_4, FORWARDING);
    // root2 and root3 reproduce root1's InboxRules_alice.json byte-for-byte (both rules survive
    // unmodified) - genuine duplicate_file sightings of both rules, not fresh parses.
    write_rules(&root4, ALICE, "alice", &[inbox_rule("alice", 1111, ".")]);

    let mut case = Case::in_memory().unwrap();
    ingest(&mut case, &root1);
    ingest(&mut case, &root2);
    ingest(&mut case, &root3);
    ingest(&mut case, &root4);
    case.conn()
        .execute(
            &format!(
                "UPDATE collections SET collected_at = NULL WHERE collection_id = {}",
                collection_id_for(&case, STAMP_2)
            ),
            [],
        )
        .unwrap();

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
                 WHERE table_name = 'inbox_rules' AND record_key = '{removed_key}'
                   AND absent_from_collection_id = {}",
                collection_id_for(&case, STAMP_4)
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
