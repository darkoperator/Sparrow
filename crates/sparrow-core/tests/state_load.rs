use duckdb::params;
use sparrow_core::db::state_tables::{
    COLLECTOR_FLAGS, INBOX_RULES, REMOTE_DOMAINS, RISK_DETECTIONS,
};
use sparrow_core::ingest::IngestOptions;
use sparrow_core::ingest::context::ParseContext;
use sparrow_core::ingest::state::{LoadOutcome, StagedRow, load_rows};
use sparrow_core::normalize::fields::Cell;
use sparrow_core::parsers::records::SourceRecord;
use sparrow_core::parsers::stage::{TableRows, load_tables};
use sparrow_core::readers::text::{LineIndex, SourcePos, Span, decode};
use sparrow_core::{Case, Error};

fn collection(case: &Case, name: &str, collected_at: Option<&str>) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO collections (tool, root_path, collected_at, sparrow_version)
             VALUES ('hawk', ?, CAST(? AS TIMESTAMPTZ), 't') RETURNING collection_id",
            params![format!("/cases/{name}"), collected_at],
            |r| r.get(0),
        )
        .unwrap()
}

fn file(case: &Case, collection_id: i64) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status)
             VALUES (?, 'x.json', 1, 'h', 'parsed') RETURNING file_id",
            params![collection_id],
            |r| r.get(0),
        )
        .unwrap()
}

const RULE_COLS: &[&str] = &[
    "kind",
    "mailbox",
    "mailbox_upn",
    "rule_identity",
    "name",
    "forward_to",
    "priority",
];

fn rule(ord: u64, key: &str, upn: Option<&str>, name: &str, fwd: Option<&str>) -> StagedRow {
    StagedRow {
        ordinal: ord,
        pos: SourcePos {
            line_start: 1 + ord as u32,
            line_end: 1 + ord as u32,
            byte_offset: ord * 10,
            byte_length: 10,
        },
        raw_sha256: format!("sha{ord}"),
        record_key: key.into(),
        cells: vec![
            Some("inbox".into()),
            Some("alice".into()),
            upn.map(Into::into),
            Some("1".into()),
            Some(name.into()),
            fwd.map(|f| format!("[\"{f}\"]")),
            Some("0".into()),
        ],
        raw: Some(format!("{{\"Name\":\"{name}\",\"Ord\":{ord}}}")),
    }
}

fn text(case: &Case, sql: &str) -> String {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn new_rows_insert_and_repeats_in_a_batch_are_duplicates() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", Some("2026-09-10T00:00:00Z"));
    let f = file(&case, c);
    let rows = [
        rule(
            0,
            "k1",
            Some("alice@contoso.example"),
            "Fwd",
            Some("x@fabrikam.example"),
        ),
        rule(1, "k1", None, "Other", None),
        rule(2, "k2", None, "Move", None),
    ];
    let out = load_rows(case.conn(), &INBOX_RULES, RULE_COLS, c, f, &rows).unwrap();
    assert_eq!(
        out,
        LoadOutcome {
            staged: 3,
            inserted: 2,
            updated: 0
        }
    );
    assert_eq!(out.duplicate(), 1);
    assert_eq!(
        text(
            &case,
            "SELECT name FROM inbox_rules WHERE record_key = 'k1'"
        ),
        "Fwd"
    );
    assert_eq!(
        text(
            &case,
            "SELECT forward_to[1] FROM inbox_rules WHERE record_key = 'k1'"
        ),
        "x@fabrikam.example"
    );
    assert_eq!(
        text(
            &case,
            "SELECT CAST(kind AS VARCHAR) FROM inbox_rules WHERE record_key = 'k2'"
        ),
        "inbox"
    );
    assert_eq!(
        text(
            &case,
            "SELECT CAST(collected_at AS VARCHAR) FROM inbox_rules WHERE record_key = 'k2'"
        ),
        text(
            &case,
            &format!(
                "SELECT CAST(collected_at AS VARCHAR) FROM collections WHERE collection_id = {c}"
            )
        )
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'inbox_rules'"
        ),
        3
    );
}

#[test]
fn unchanged_copy_is_a_duplicate_and_changed_copy_updates_and_merges_raw() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", None);
    let (f1, f2, f3) = (file(&case, c), file(&case, c), file(&case, c));
    let base = rule(0, "k1", Some("alice@contoso.example"), "Fwd", None);
    load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        c,
        f1,
        std::slice::from_ref(&base),
    )
    .unwrap();
    let same = load_rows(case.conn(), &INBOX_RULES, RULE_COLS, c, f2, &[base]).unwrap();
    assert_eq!((same.inserted, same.updated, same.duplicate()), (0, 0, 1));
    let changed = rule(5, "k1", Some("alice@contoso.example"), "Renamed", None);
    let out = load_rows(case.conn(), &INBOX_RULES, RULE_COLS, c, f3, &[changed]).unwrap();
    assert_eq!((out.inserted, out.updated), (0, 1));
    assert_eq!(
        text(
            &case,
            "SELECT name FROM inbox_rules WHERE record_key = 'k1'"
        ),
        "Renamed"
    );
    assert_eq!(
        text(
            &case,
            "SELECT raw->>'$.Ord' FROM inbox_rules WHERE record_key = 'k1'"
        ),
        "5"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM inbox_rules"), 1);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE record_key = 'k1'"
        ),
        3
    );
}

#[test]
fn older_collection_never_replaces_newer_and_undated_falls_back_to_ingest_order() {
    let case = Case::in_memory().unwrap();
    let newer = collection(&case, "new", Some("2026-09-20T09:00:00Z"));
    let older = collection(&case, "old", Some("2026-09-10T09:00:00Z"));
    load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        newer,
        file(&case, newer),
        &[rule(0, "k1", None, "New", None)],
    )
    .unwrap();
    let out = load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        older,
        file(&case, older),
        &[rule(0, "k1", None, "Old", None)],
    )
    .unwrap();
    assert_eq!((out.updated, out.duplicate()), (0, 1));
    assert_eq!(text(&case, "SELECT name FROM inbox_rules"), "New");
    assert_eq!(count(&case, "SELECT collection_id FROM inbox_rules"), newer);
    let undated = collection(&case, "undated", None);
    let out = load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        undated,
        file(&case, undated),
        &[rule(0, "k1", None, "Undated", None)],
    )
    .unwrap();
    assert_eq!(out.updated, 1);
    assert_eq!(text(&case, "SELECT name FROM inbox_rules"), "Undated");
    assert!(
        count(
            &case,
            "SELECT count(*) FROM inbox_rules WHERE collected_at IS NULL"
        ) == 1,
        "collected_at follows the writing collection"
    );
}

#[test]
fn keep_when_null_columns_keep_the_stored_value() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", None);
    load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        c,
        file(&case, c),
        &[rule(0, "k1", Some("alice@contoso.example"), "Fwd", None)],
    )
    .unwrap();
    let out = load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        c,
        file(&case, c),
        &[rule(0, "k1", None, "Fwd", None)],
    )
    .unwrap();
    assert_eq!(
        out.duplicate(),
        1,
        "a NULL in a keep_when_null column is not a change"
    );
    load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        c,
        file(&case, c),
        &[rule(0, "k1", None, "Renamed", None)],
    )
    .unwrap();
    assert_eq!(
        text(&case, "SELECT mailbox_upn FROM inbox_rules"),
        "alice@contoso.example"
    );
    assert_eq!(text(&case, "SELECT name FROM inbox_rules"), "Renamed");
}

#[test]
fn insert_only_tables_never_update() {
    let case = Case::in_memory().unwrap();
    let old = collection(&case, "old", Some("2026-09-10T00:00:00Z"));
    let new = collection(&case, "new", Some("2026-09-20T00:00:00Z"));
    let cols: &[&str] = &["file_id", "flag_type", "description"];
    let flag = |desc: &str| StagedRow {
        cells: vec![
            Some("1".into()),
            Some("inbox_rule".into()),
            Some(desc.into()),
        ],
        ..rule(0, "f1", None, "x", None)
    };
    load_rows(
        case.conn(),
        &COLLECTOR_FLAGS,
        cols,
        old,
        file(&case, old),
        &[flag("a")],
    )
    .unwrap();
    let out = load_rows(
        case.conn(),
        &COLLECTOR_FLAGS,
        cols,
        new,
        file(&case, new),
        &[flag("b")],
    )
    .unwrap();
    assert_eq!((out.inserted, out.updated, out.duplicate()), (0, 0, 1));
    assert_eq!(text(&case, "SELECT description FROM collector_flags"), "a");
}

#[test]
fn struct_json_and_time_columns_cast() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", None);
    let cols: &[&str] = &[
        "detection_id",
        "location",
        "additional_info",
        "detected_time",
    ];
    let row = StagedRow {
        cells: vec![
            Some("d-1".into()),
            Some(
                r#"{"city":"Lisbon","state":null,"country":"PT","latitude":38.7,"longitude":-9.1}"#
                    .into(),
            ),
            Some(r#"{"userAgent":"python-requests/2.31"}"#.into()),
            Some("2026-09-01T10:00:00+00:00".into()),
        ],
        ..rule(0, "d-1", None, "x", None)
    };
    load_rows(
        case.conn(),
        &RISK_DETECTIONS,
        cols,
        c,
        file(&case, c),
        &[row],
    )
    .unwrap();
    assert_eq!(
        text(&case, "SELECT location.city FROM risk_detections"),
        "Lisbon"
    );
    assert_eq!(
        text(
            &case,
            "SELECT additional_info->>'$.userAgent' FROM risk_detections"
        ),
        "python-requests/2.31"
    );
    assert_eq!(
        count(
            &case,
            "SELECT epoch(detected_time)::BIGINT FROM risk_detections"
        ),
        1_788_256_800
    );
}

#[test]
fn unknown_column_is_an_error() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", None);
    let row = StagedRow {
        cells: vec![Some("x".into())],
        ..rule(0, "k", None, "x", None)
    };
    let err = load_rows(
        case.conn(),
        &INBOX_RULES,
        &["nope"],
        c,
        file(&case, c),
        &[row],
    )
    .unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "{err}");
}

fn record(ord: u64, start: usize, end: usize) -> SourceRecord {
    SourceRecord {
        ordinal: ord,
        span: Span { start, end },
        map: serde_json::Map::new(),
        field_spans: Vec::new(),
    }
}

#[test]
fn load_tables_counts_rows_and_turns_bad_times_into_parse_errors() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", None);
    let f = file(&case, c);
    let raw = b"line one\nline two\n";
    let text = decode(raw);
    let index = LineIndex::new(&text.text);
    let opts = IngestOptions::default();
    let mut ctx = ParseContext::new(
        case.conn(),
        c,
        f,
        "Tenant/RemoteDomain.json",
        None,
        raw,
        &text,
        &index,
        &opts,
    );
    let mut t = TableRows::new(&REMOTE_DOMAINS, &["domain_name", "when_changed"]);
    t.push(
        &record(0, 0, 8),
        "a.example".into(),
        vec![
            Cell::text(Some("a.example".into())),
            Cell::time(Some("9/24/2026 1:00:00 PM".into())),
        ],
    );
    t.push(
        &record(1, 9, 17),
        "b.example".into(),
        vec![
            Cell::text(Some("b.example".into())),
            Cell::time(Some("not a date".into())),
        ],
    );
    load_tables(&mut ctx, vec![t]).unwrap();
    let (stats, _) = ctx.finish();
    assert_eq!(
        (stats.read, stats.loaded, stats.duplicate, stats.error),
        (2, 1, 0, 1)
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM parse_errors WHERE line_start = 2"
        ),
        1
    );
}

#[test]
fn load_tables_fails_the_file_when_every_date_is_ambiguous() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", None);
    let f = file(&case, c);
    let raw = b"line one\n";
    let text = decode(raw);
    let index = LineIndex::new(&text.text);
    let opts = IngestOptions::default();
    let mut ctx = ParseContext::new(
        case.conn(),
        c,
        f,
        "Tenant/RemoteDomain.json",
        None,
        raw,
        &text,
        &index,
        &opts,
    );
    let mut t = TableRows::new(&REMOTE_DOMAINS, &["domain_name", "when_changed"]);
    t.push(
        &record(0, 0, 8),
        "a.example".into(),
        vec![
            Cell::text(Some("a.example".into())),
            Cell::time(Some("6/9/2026 1:00:00 PM".into())),
        ],
    );
    let err = load_tables(&mut ctx, vec![t]).unwrap_err();
    assert!(err.to_string().contains("--culture"), "{err}");
}
