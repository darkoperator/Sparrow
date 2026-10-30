use serde_json::{Value, json};
use sparrow_core::Case;
use sparrow_core::ingest::bulk::{LoadOutcome, StagedUal, load_ual_batch};
use sparrow_core::normalize::ual::{UalRecord, normalize_audit};
use sparrow_core::normalize::ual_shape::{detect_shape, to_audit};
use sparrow_core::readers::text::SourcePos;
use sparrow_core::readers::time::DateOrder;

const MIA: &str = "a2222222-2222-4222-8222-222222222222";
const RULE: &str = "a1111111-1111-4111-8111-111111111111";
const LINK: &str = "a5555555-5555-4555-8555-555555555555";

fn rec(v: Value, lossy: bool) -> UalRecord {
    let map = v.as_object().unwrap().clone();
    let shape = detect_shape(map.keys().map(String::as_str), false);
    normalize_audit(
        &to_audit(shape, &map, lossy).unwrap(),
        Some(DateOrder::MonthFirst),
    )
    .unwrap()
}

fn mia_full() -> UalRecord {
    rec(
        json!({
            "CreationTime": "2026-09-01T10:05:00", "Id": MIA, "Operation": "MailItemsAccessed",
            "Workload": "Exchange", "RecordType": 50, "UserId": "alice@contoso.example",
            "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind"}],
            "Folders": [{"Path": "\\Inbox", "FolderItems": [
                {"InternetMessageId": "<m1@contoso.example>", "SizeInBytes": 1},
                {"InternetMessageId": "<m2@contoso.example>", "SizeInBytes": 2}
            ]}]
        }),
        false,
    )
}

fn mia_partial() -> UalRecord {
    rec(
        json!({
            "CreationTime": "2026-09-01T10:05:00", "Id": MIA, "Operation": "MailItemsAccessed",
            "Folders": "System.Object[]"
        }),
        true,
    )
}

fn rule() -> UalRecord {
    rec(
        json!({
            "CreationTime": "2026-09-01T10:00:00", "Id": RULE, "Operation": "New-InboxRule",
            "RecordType": 1, "Workload": "Exchange",
            "Parameters": [{"Name": "ForwardTo", "Value": "x@fabrikam.example"}]
        }),
        false,
    )
}

fn link() -> UalRecord {
    rec(
        json!({
            "CreationTime": "2026-09-01T10:12:00", "Id": LINK, "Operation": "AnonymousLinkCreated",
            "Workload": "OneDrive", "SourceFileName": "Invoice 2026.one", "ItemType": "File",
            "EventData": "<Type>View</Type>", "TargetUserOrGroupType": "Guest"
        }),
        false,
    )
}

fn staged(ordinal: u64, rec: UalRecord) -> StagedUal {
    StagedUal {
        ordinal,
        pos: SourcePos {
            line_start: ordinal as u32 + 2,
            line_end: ordinal as u32 + 2,
            byte_offset: ordinal * 100,
            byte_length: 100,
        },
        raw_sha256: format!("sha{ordinal}"),
        rec,
    }
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn new_records_are_inserted_with_children_and_sightings() {
    let case = Case::in_memory().unwrap();
    let out = load_ual_batch(case.conn(), 7, 1, &[staged(0, mia_full())]).unwrap();
    assert_eq!(
        out,
        LoadOutcome {
            staged: 1,
            inserted: 1,
            upgraded: 0
        }
    );
    assert_eq!(out.duplicate(), 0);
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed WHERE collection_id = 7 AND internet_message_id IS NOT NULL"
        ),
        2
    );
    let (line, sha, file): (i64, String, i64) = case
        .conn()
        .query_row(
            "SELECT line_start, raw_sha256, file_id FROM record_sources
             WHERE table_name = 'ual_events' AND record_key = ?",
            [MIA],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((line, sha.as_str(), file), (2, "sha0", 1));
}

#[test]
fn same_record_from_another_file_is_a_duplicate_with_a_second_sighting() {
    let case = Case::in_memory().unwrap();
    load_ual_batch(case.conn(), 7, 1, &[staged(0, mia_full())]).unwrap();
    let out = load_ual_batch(case.conn(), 7, 2, &[staged(5, mia_full())]).unwrap();
    assert_eq!((out.inserted, out.upgraded, out.duplicate()), (0, 0, 1));
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM mail_items_accessed"), 2);
    assert_eq!(count(&case, "SELECT count(*) FROM record_sources"), 2);
}

#[test]
fn duplicate_within_one_batch_keeps_one_row_and_both_sightings() {
    let case = Case::in_memory().unwrap();
    let out = load_ual_batch(case.conn(), 7, 1, &[staged(0, rule()), staged(1, rule())]).unwrap();
    assert_eq!((out.staged, out.inserted, out.duplicate()), (2, 1, 1));
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 1);
    assert_eq!(count(&case, "SELECT count(*) FROM record_sources"), 2);
}

#[test]
fn full_record_upgrades_partial_row_and_replaces_children() {
    let case = Case::in_memory().unwrap();
    load_ual_batch(case.conn(), 7, 1, &[staged(0, mia_partial())]).unwrap();
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed WHERE internet_message_id IS NULL"
        ),
        1
    );
    let out = load_ual_batch(case.conn(), 8, 2, &[staged(0, mia_full())]).unwrap();
    assert_eq!(
        out,
        LoadOutcome {
            staged: 1,
            inserted: 0,
            upgraded: 1
        }
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'full' AND collection_id = 7"
        ),
        1
    );
    assert_eq!(count(&case, "SELECT count(*) FROM mail_items_accessed"), 2);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM mail_items_accessed WHERE internet_message_id IS NOT NULL AND collection_id = 7"
        ),
        2
    );
    assert_eq!(count(&case, "SELECT count(*) FROM record_sources"), 2);
}

#[test]
fn partial_after_full_is_only_a_duplicate() {
    let case = Case::in_memory().unwrap();
    load_ual_batch(case.conn(), 7, 1, &[staged(0, mia_full())]).unwrap();
    let out = load_ual_batch(case.conn(), 7, 2, &[staged(0, mia_partial())]).unwrap();
    assert_eq!((out.inserted, out.upgraded, out.duplicate()), (0, 0, 1));
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'full'"
        ),
        1
    );
    assert_eq!(count(&case, "SELECT count(*) FROM mail_items_accessed"), 2);
}

#[test]
fn full_copy_wins_inside_one_batch() {
    let case = Case::in_memory().unwrap();
    let out = load_ual_batch(
        case.conn(),
        7,
        1,
        &[staged(0, mia_partial()), staged(1, mia_full())],
    )
    .unwrap();
    assert_eq!((out.inserted, out.duplicate()), (1, 1));
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE data_completeness = 'full'"
        ),
        1
    );
    assert_eq!(count(&case, "SELECT count(*) FROM mail_items_accessed"), 2);
}

#[test]
fn typed_columns_and_children_round_trip() {
    let case = Case::in_memory().unwrap();
    load_ual_batch(case.conn(), 7, 1, &[staged(0, rule()), staged(1, link())]).unwrap();
    let row: (String, String, String, String, String, String, bool) = case
        .conn()
        .query_row(
            "SELECT parameters['ForwardTo'], CAST(event_time AS VARCHAR), CAST(record_id AS VARCHAR),
                    CAST(data_completeness AS VARCHAR), CAST(time_precision AS VARCHAR), record_type_name,
                    time_tz_assumed
             FROM ual_events WHERE operation = 'New-InboxRule'",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        row,
        (
            "x@fabrikam.example".into(),
            "2026-09-01 10:00:00+00".into(),
            RULE.into(),
            "full".into(),
            "second".into(),
            "ExchangeAdmin".into(),
            true
        )
    );
    let (link_type, permission, external): (String, String, bool) = case
        .conn()
        .query_row(
            "SELECT CAST(link_type AS VARCHAR), CAST(permission AS VARCHAR), is_external FROM sharing_events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (link_type.as_str(), permission.as_str(), external),
        ("anonymous", "view", true)
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM file_events WHERE is_onenote AND item_type = 'file'"
        ),
        1
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE operation = 'AnonymousLinkCreated' AND parameters IS NULL"
        ),
        1
    );
}

#[test]
fn rollback_discards_rows_and_sightings_and_staging_recovers() {
    let mut case = Case::in_memory().unwrap();
    {
        let tx = case.conn_mut().transaction().unwrap();
        load_ual_batch(&tx, 7, 1, &[staged(0, mia_full())]).unwrap();
        tx.rollback().unwrap();
    }
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), 0);
    assert_eq!(count(&case, "SELECT count(*) FROM mail_items_accessed"), 0);
    assert_eq!(count(&case, "SELECT count(*) FROM record_sources"), 0);
    let out = load_ual_batch(case.conn(), 7, 1, &[staged(0, mia_full())]).unwrap();
    assert_eq!(out.inserted, 1);
}

#[test]
fn empty_batch_is_a_no_op() {
    let case = Case::in_memory().unwrap();
    assert_eq!(
        load_ual_batch(case.conn(), 7, 1, &[]).unwrap(),
        LoadOutcome::default()
    );
}

#[test]
fn a_files_own_full_copy_in_a_later_batch_is_a_duplicate_not_an_upgrade() {
    // One batch keeps the file's full copy over its partial one (stage_chosen); split over two batches of the same
    // file, the full copy upgrades the partial row: same rows, and the counts must say the same.
    let snapshot = |case: &Case| -> Vec<String> {
        let mut stmt = case
            .conn()
            .prepare(
                "SELECT 'e|' || record_id || '|' || data_completeness || '|' || audit_data::VARCHAR FROM ual_events
                 UNION ALL SELECT 'm|' || record_id || '|' || internet_message_id FROM mail_items_accessed
                 UNION ALL SELECT 's|' || record_key || '|' || file_id || '|' || record_ordinal FROM record_sources
                 ORDER BY 1",
            )
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let one = Case::in_memory().unwrap();
    let whole = load_ual_batch(
        one.conn(),
        7,
        1,
        &[staged(0, mia_partial()), staged(1, mia_full())],
    )
    .unwrap();
    assert_eq!(
        whole,
        LoadOutcome {
            staged: 2,
            inserted: 1,
            upgraded: 0
        }
    );
    let two = Case::in_memory().unwrap();
    let first = load_ual_batch(two.conn(), 7, 1, &[staged(0, mia_partial())]).unwrap();
    let second = load_ual_batch(two.conn(), 7, 1, &[staged(1, mia_full())]).unwrap();
    assert_eq!((first.inserted, first.upgraded), (1, 0));
    assert_eq!(
        second,
        LoadOutcome {
            staged: 1,
            inserted: 0,
            upgraded: 0
        }
    );
    assert_eq!(second.duplicate(), 1);
    assert_eq!(snapshot(&one), snapshot(&two));
    assert!(snapshot(&two).iter().any(|r| r.contains("|full|")));
}

#[test]
fn a_row_stored_before_the_file_is_still_upgraded_across_its_batches() {
    // An earlier file stored the partial row. This file has a partial copy (batch 1, only a sighting) and a full
    // one (batch 2): that is a real upgrade, as one batch of both copies reports it.
    let prior = |case: &Case| {
        load_ual_batch(case.conn(), 7, 1, &[staged(0, mia_partial())]).unwrap();
    };
    let one = Case::in_memory().unwrap();
    prior(&one);
    let whole = load_ual_batch(
        one.conn(),
        7,
        2,
        &[staged(0, mia_partial()), staged(1, mia_full())],
    )
    .unwrap();
    assert_eq!(
        (whole.inserted, whole.upgraded, whole.duplicate()),
        (0, 1, 1)
    );
    let two = Case::in_memory().unwrap();
    prior(&two);
    let a = load_ual_batch(two.conn(), 7, 2, &[staged(0, mia_partial())]).unwrap();
    let b = load_ual_batch(two.conn(), 7, 2, &[staged(1, mia_full())]).unwrap();
    assert_eq!(
        (
            a.inserted + b.inserted,
            a.upgraded + b.upgraded,
            a.duplicate() + b.duplicate()
        ),
        (0, 1, 1)
    );
}

#[test]
fn split_batches_count_like_one_for_every_completeness_order() {
    let snapshot = |case: &Case| -> Vec<String> {
        let mut stmt = case
            .conn()
            .prepare(
                "SELECT 'e|' || record_id || '|' || data_completeness || '|' || audit_data::VARCHAR FROM ual_events
                 UNION ALL SELECT 'm|' || record_id || '|' || coalesce(internet_message_id, '') FROM mail_items_accessed
                 UNION ALL SELECT 's|' || record_key || '|' || file_id || '|' || record_ordinal FROM record_sources
                 ORDER BY 1",
            )
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    type Make = fn() -> UalRecord;
    let orders: [(&str, Make, Make); 4] = [
        ("partial,full", mia_partial, mia_full),
        ("full,partial", mia_full, mia_partial),
        ("full,full", mia_full, mia_full),
        ("partial,partial", mia_partial, mia_partial),
    ];
    for (name, x, y) in orders {
        let one = Case::in_memory().unwrap();
        let w = load_ual_batch(one.conn(), 7, 1, &[staged(0, x()), staged(1, y())]).unwrap();
        let two = Case::in_memory().unwrap();
        let a = load_ual_batch(two.conn(), 7, 1, &[staged(0, x())]).unwrap();
        let b = load_ual_batch(two.conn(), 7, 1, &[staged(1, y())]).unwrap();
        assert_eq!(
            (w.inserted, w.upgraded, w.duplicate()),
            (
                a.inserted + b.inserted,
                a.upgraded + b.upgraded,
                a.duplicate() + b.duplicate()
            ),
            "{name}"
        );
        assert_eq!(snapshot(&one), snapshot(&two), "{name}");
    }
}
