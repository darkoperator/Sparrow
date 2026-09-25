use duckdb::params;
use sparrow_core::db::state_tables::{
    ADMIN_AUDIT_EVENTS, COLLECTOR_FLAGS, INBOX_RULES, MAILBOXES, REMOTE_DOMAINS, RISK_DETECTIONS,
    SIGNINS,
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
fn newest_unchanged_copy_still_advances_the_stored_collection() {
    // Ingest order A (oldest), C (newest, same value as A), B (middle, a different value).
    // C must win: once C's unchanged copy is merged in, B (older than C) must not replace it.
    let case = Case::in_memory().unwrap();
    let a = collection(&case, "a", Some("2026-09-10T00:00:00Z"));
    let c = collection(&case, "c", Some("2026-09-20T00:00:00Z"));
    let b = collection(&case, "b", Some("2026-09-15T00:00:00Z"));
    load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        a,
        file(&case, a),
        &[rule(0, "k1", None, "X", None)],
    )
    .unwrap();
    let out_c = load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        c,
        file(&case, c),
        &[rule(0, "k1", None, "X", None)],
    )
    .unwrap();
    assert_eq!(
        (out_c.updated, out_c.duplicate()),
        (0, 1),
        "unchanged values are not counted as an update"
    );
    assert_eq!(
        count(&case, "SELECT collection_id FROM inbox_rules"),
        c,
        "the row must still advance to C's collection even though nothing changed"
    );
    let out_b = load_rows(
        case.conn(),
        &INBOX_RULES,
        RULE_COLS,
        b,
        file(&case, b),
        &[rule(0, "k1", None, "Y", None)],
    )
    .unwrap();
    assert_eq!((out_b.updated, out_b.duplicate()), (0, 1));
    assert_eq!(
        text(&case, "SELECT name FROM inbox_rules"),
        "X",
        "B is older than the row's current (C) collection and must not replace it"
    );
    assert_eq!(count(&case, "SELECT collection_id FROM inbox_rules"), c);
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

/// Mailbox row for alice with `cells` aligned to `cols` (upn first).
fn mbx(cells: &[Option<&str>], raw: &str) -> StagedRow {
    StagedRow {
        cells: cells.iter().map(|c| c.map(Into::into)).collect(),
        raw: Some(raw.into()),
        ..rule(0, "alice@contoso.example", None, "x", None)
    }
}

type Load<'a> = (i64, &'a [&'a str], StagedRow);

/// Loads `loads` in order into a fresh case; returns the case.
fn load_in_order(
    dated: &[(&str, Option<&str>)],
    order: &[usize],
    loads: &[Load],
) -> (Case, Vec<LoadOutcome>) {
    let case = Case::in_memory().unwrap();
    let ids: Vec<i64> = dated
        .iter()
        .map(|(name, at)| collection(&case, name, *at))
        .collect();
    let mut outs = Vec::new();
    for &i in order {
        let (c, cols, row) = &loads[i];
        let cid = ids[*c as usize];
        outs.push(
            load_rows(
                case.conn(),
                &MAILBOXES,
                cols,
                cid,
                file(&case, cid),
                std::slice::from_ref(row),
            )
            .unwrap(),
        );
    }
    (case, outs)
}

const MBX_STATE: &str = "SELECT coalesce(forwarding_smtp_address, '-') || '|' || coalesce(auto_reply_state, '-') || '|' || coalesce(display_name, '-') || '|' || collection_id FROM mailboxes";

/// Final mailbox values plus `column_collections` as a key-sorted map.
fn mbx_state(case: &Case) -> (String, std::collections::BTreeMap<String, i64>) {
    let cc = text(
        case,
        "SELECT CAST(column_collections AS VARCHAR) FROM mailboxes",
    );
    (text(case, MBX_STATE), serde_json::from_str(&cc).unwrap())
}

const NEWER_OLDER: &[(&str, Option<&str>)] = &[
    ("newer", Some("2026-09-20T00:00:00Z")),
    ("older", Some("2026-09-10T00:00:00Z")),
];

#[test]
fn older_collection_fills_columns_the_newer_one_never_provided_in_either_order() {
    let fwd: &[&str] = &["upn", "forwarding_smtp_address"];
    let ar: &[&str] = &["upn", "auto_reply_state"];
    let loads: Vec<Load> = vec![
        (
            0,
            fwd,
            mbx(
                &[
                    Some("alice@contoso.example"),
                    Some("smtp:x@fabrikam.example"),
                ],
                r#"{"ForwardingSmtpAddress":"smtp:x@fabrikam.example"}"#,
            ),
        ),
        (
            1,
            ar,
            mbx(
                &[Some("alice@contoso.example"), Some("Enabled")],
                r#"{"AutoReplyState":"Enabled"}"#,
            ),
        ),
    ];
    let mut finals = Vec::new();
    for order in [[0, 1], [1, 0]] {
        let (case, outs) = load_in_order(NEWER_OLDER, &order, &loads);
        assert_eq!(
            (outs[1].inserted, outs[1].updated),
            (0, 1),
            "order {order:?}: the second load writes a column"
        );
        assert_eq!(
            text(
                &case,
                "SELECT forwarding_smtp_address || '|' || auto_reply_state FROM mailboxes"
            ),
            "smtp:x@fabrikam.example|Enabled",
            "order {order:?}"
        );
        let newer = count(
            &case,
            "SELECT collection_id FROM collections WHERE root_path = '/cases/newer'",
        );
        let older = count(
            &case,
            "SELECT collection_id FROM collections WHERE root_path = '/cases/older'",
        );
        assert_eq!(
            count(&case, "SELECT collection_id FROM mailboxes"),
            newer,
            "order {order:?}"
        );
        assert_eq!(
            count(
                &case,
                "SELECT CAST(column_collections->>'$.auto_reply_state' AS BIGINT) FROM mailboxes"
            ),
            older,
            "order {order:?}"
        );
        assert_eq!(
            count(
                &case,
                "SELECT CAST(column_collections->>'$.forwarding_smtp_address' AS BIGINT) FROM mailboxes"
            ),
            newer,
            "order {order:?}"
        );
        assert_eq!(
            text(
                &case,
                "SELECT raw->>'$.AutoReplyState' || '|' || (raw->>'$.ForwardingSmtpAddress') FROM mailboxes"
            ),
            "Enabled|smtp:x@fabrikam.example",
            "order {order:?}: raw carries both sources"
        );
        finals.push(mbx_state(&case));
    }
    assert_eq!(finals[0], finals[1]);
}

#[test]
fn newer_null_is_not_resurrected_by_an_older_value_in_either_order() {
    let fwd: &[&str] = &["upn", "forwarding_smtp_address"];
    let loads: Vec<Load> = vec![
        (
            0,
            fwd,
            mbx(
                &[Some("alice@contoso.example"), None],
                r#"{"ForwardingSmtpAddress":null}"#,
            ),
        ),
        (
            1,
            fwd,
            mbx(
                &[
                    Some("alice@contoso.example"),
                    Some("smtp:x@fabrikam.example"),
                ],
                r#"{"ForwardingSmtpAddress":"smtp:x@fabrikam.example"}"#,
            ),
        ),
    ];
    let mut finals = Vec::new();
    for order in [[0, 1], [1, 0]] {
        let (case, _) = load_in_order(NEWER_OLDER, &order, &loads);
        assert_eq!(
            count(
                &case,
                "SELECT count(*) FROM mailboxes WHERE forwarding_smtp_address IS NULL"
            ),
            1,
            "order {order:?}: the newer capture cleared forwarding"
        );
        finals.push(mbx_state(&case));
    }
    assert_eq!(finals[0], finals[1]);
}

#[test]
fn keep_when_null_columns_take_the_newest_non_null_value_in_any_order() {
    // display_name is keep_when_null: a NULL never claims the column.
    let cols: &[&str] = &["upn", "display_name"];
    let dated: &[(&str, Option<&str>)] = &[
        ("a", Some("2026-09-10T00:00:00Z")),
        ("b", Some("2026-09-15T00:00:00Z")),
        ("c", Some("2026-09-20T00:00:00Z")),
    ];
    let loads: Vec<Load> = vec![
        (
            0,
            cols,
            mbx(&[Some("alice@contoso.example"), Some("Old")], "{}"),
        ),
        (
            1,
            cols,
            mbx(&[Some("alice@contoso.example"), Some("Mid")], "{}"),
        ),
        (2, cols, mbx(&[Some("alice@contoso.example"), None], "{}")),
    ];
    let mut finals = Vec::new();
    for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
        let (case, _) = load_in_order(dated, &order, &loads);
        assert_eq!(
            text(&case, "SELECT display_name FROM mailboxes"),
            "Mid",
            "order {order:?}"
        );
        finals.push(mbx_state(&case));
    }
    assert!(finals.windows(2).all(|w| w[0] == w[1]), "{finals:#?}");
}

#[test]
fn merged_raw_ignores_top_level_nulls() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", None);
    let cols: &[&str] = &["upn", "auto_reply_state"];
    load_rows(
        case.conn(),
        &MAILBOXES,
        cols,
        c,
        file(&case, c),
        &[mbx(
            &[Some("alice@contoso.example"), Some("Enabled")],
            r#"{"Keep":"x","AutoReplyState":"Enabled"}"#,
        )],
    )
    .unwrap();
    load_rows(
        case.conn(),
        &MAILBOXES,
        cols,
        c,
        file(&case, c),
        &[mbx(
            &[Some("alice@contoso.example"), Some("Disabled")],
            r#"{"Keep":null,"AutoReplyState":"Disabled"}"#,
        )],
    )
    .unwrap();
    assert_eq!(
        text(
            &case,
            "SELECT raw->>'$.Keep' || '|' || (raw->>'$.AutoReplyState') FROM mailboxes"
        ),
        "x|Disabled"
    );
}

fn signin(
    ord: u64,
    key: &str,
    upn: Option<&str>,
    app: Option<&str>,
    session: Option<&str>,
) -> StagedRow {
    StagedRow {
        ordinal: ord,
        pos: SourcePos {
            line_start: 1 + ord as u32,
            line_end: 1 + ord as u32,
            byte_offset: ord * 10,
            byte_length: 10,
        },
        raw_sha256: format!("s{ord}"),
        record_key: key.into(),
        cells: vec![
            Some(key.into()),
            upn.map(Into::into),
            app.map(Into::into),
            session.map(Into::into),
        ],
        raw: Some(format!("{{\"Id\":\"{key}\",\"Ord\":{ord}}}")),
    }
}

const SIGNIN_COLS: &[&str] = &["signin_id", "user_upn", "app_name", "session_id"];

#[test]
fn fill_missing_keeps_the_first_copy_and_fills_nulls() {
    let case = Case::in_memory().unwrap();
    let c1 = collection(&case, "a", Some("2026-09-10T00:00:00Z"));
    let c2 = collection(&case, "b", Some("2026-09-20T00:00:00Z"));
    let first = load_rows(
        case.conn(),
        &SIGNINS,
        SIGNIN_COLS,
        c1,
        file(&case, c1),
        &[signin(0, "s1", Some("alice@contoso.example"), None, None)],
    )
    .unwrap();
    assert_eq!((first.inserted, first.updated), (1, 0));
    // A newer copy with a different UPN and the app name: the UPN stays, the app name fills.
    let second = load_rows(
        case.conn(),
        &SIGNINS,
        SIGNIN_COLS,
        c2,
        file(&case, c2),
        &[signin(
            1,
            "s1",
            Some("mallory@fabrikam.example"),
            Some("Outlook"),
            None,
        )],
    )
    .unwrap();
    assert_eq!(
        (second.inserted, second.updated, second.duplicate()),
        (0, 1, 0)
    );
    assert_eq!(
        text(
            &case,
            "SELECT user_upn || '|' || app_name || '|' || collection_id FROM signins"
        ),
        format!("alice@contoso.example|Outlook|{c1}")
    );
    assert_eq!(
        count(
            &case,
            &format!(
                "SELECT count(*) FROM signins WHERE (column_collections->>'$.app_name' = '{c2}') AND (column_collections->>'$.user_upn' = '{c1}')"
            )
        ),
        1
    );
    assert_eq!(text(&case, "SELECT raw->>'$.Ord' FROM signins"), "0");
    // The same copy again only adds a sighting.
    let third = load_rows(
        case.conn(),
        &SIGNINS,
        SIGNIN_COLS,
        c2,
        file(&case, c2),
        &[signin(
            1,
            "s1",
            Some("mallory@fabrikam.example"),
            Some("Outlook"),
            None,
        )],
    )
    .unwrap();
    assert_eq!(
        (third.inserted, third.updated, third.duplicate()),
        (0, 0, 1)
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM record_sources WHERE table_name = 'signins'"
        ),
        3
    );
}

#[test]
fn map_columns_load_from_json_objects() {
    let case = Case::in_memory().unwrap();
    let c = collection(&case, "a", None);
    let row = StagedRow {
        cells: vec![
            Some("New-InboxRule".into()),
            Some(r#"{"ForwardTo":"x@fabrikam.example","Name":"r"}"#.into()),
        ],
        ..signin(0, "k", None, None, None)
    };
    load_rows(
        case.conn(),
        &ADMIN_AUDIT_EVENTS,
        &["cmdlet", "parameters"],
        c,
        file(&case, c),
        &[row],
    )
    .unwrap();
    assert_eq!(
        text(
            &case,
            "SELECT parameters['ForwardTo'] FROM admin_audit_events"
        ),
        "x@fabrikam.example"
    );
}

#[test]
fn cell_row_sets_cells_by_column_name() {
    use sparrow_core::parsers::stage::CellRow;
    let mut r = CellRow::new(&["a", "b", "c"]);
    r.set("c", Cell::int(Some(3)))
        .set("a", Cell::text(Some("x".into())));
    assert_eq!(
        r.into_cells(),
        vec![Cell::Text("x".into()), Cell::Null, Cell::Int(3)]
    );
}

#[test]
#[should_panic(expected = "no column nope")]
fn cell_row_rejects_unknown_columns() {
    sparrow_core::parsers::stage::CellRow::new(&["a"]).set("nope", Cell::Null);
}

#[test]
fn key_time_is_utc_seconds_whatever_the_source_form() {
    use sparrow_core::parsers::stage::key_time;
    use sparrow_core::readers::time::DateOrder;
    assert_eq!(
        key_time("9/2/2026 8:00:00 AM", Some(DateOrder::MonthFirst)),
        "2026-09-02T08:00:00Z"
    );
    assert_eq!(
        key_time("/Date(1788336000123)/", None),
        "2026-09-02T08:00:00Z"
    );
    assert_eq!(
        key_time("2026-09-02T10:00:00+02:00", None),
        "2026-09-02T08:00:00Z"
    );
    assert_eq!(key_time("  not a time ", None), "not a time");
}
